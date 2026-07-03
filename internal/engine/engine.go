// Package engine implements the node's data plane: it moves IP packets
// between the virtual interface and encrypted noise sessions with peers,
// establishes direct P2P paths via NAT hole punching, and falls back to the
// relay server when a direct path can't be established. All traffic —
// direct or relayed — is end-to-end encrypted; the relay only ever sees
// ciphertext.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/noise"
	"github.com/yeungalan/vvvlan/internal/proto"
	"github.com/yeungalan/vvvlan/internal/tunio"
)

const (
	handshakeRetry   = 5 * time.Second
	rekeyInterval    = 10 * time.Minute
	sessionMaxAge    = 15 * time.Minute
	relayBindPeriod  = 25 * time.Second
	whoAmIPeriod     = 30 * time.Second
	discoKeepalive   = 15 * time.Second
	directStaleAfter = 35 * time.Second
	discoRetryPeriod = 30 * time.Second
	maxQueuedPackets = 16
)

// NetConfigurator is the subset of netcfg.Manager the engine needs; a no-op
// implementation is used in tests.
type NetConfigurator interface {
	ConfigureInterface(addr netip.Prefix, mtu int) error
	EnableExit(pin []netip.Addr) error
	DisableExit() error
	Pin(addr netip.Addr)
	EnableGatewayNAT(cidr netip.Prefix) error
	DisableGatewayNAT() error
}

// NoopConfigurator ignores all configuration calls (tests, dry runs).
type NoopConfigurator struct{}

func (NoopConfigurator) ConfigureInterface(netip.Prefix, int) error { return nil }
func (NoopConfigurator) EnableExit([]netip.Addr) error              { return nil }
func (NoopConfigurator) DisableExit() error                         { return nil }
func (NoopConfigurator) Pin(netip.Addr)                             {}
func (NoopConfigurator) EnableGatewayNAT(netip.Prefix) error        { return nil }
func (NoopConfigurator) DisableGatewayNAT() error                   { return nil }

// Config configures an Engine.
type Config struct {
	Identity     *identity.Identity
	Device       tunio.Device
	SessionToken string // authenticates relay binds
	UDPPort      int    // 0 picks an ephemeral port
	MTU          int
	Log          *slog.Logger
	NetCfg       NetConfigurator

	// AskPunch asks the control server to signal a peer to probe us
	// (WSPunchAsk). Optional.
	AskPunch func(targetNodeID string)
	// ReportEndpoints publishes our candidate endpoints to the control
	// server. Optional.
	ReportEndpoints func(endpoints []string)
	// ReportPath publishes path telemetry for the UI. Optional.
	ReportPath func(rep proto.PathReport)
}

type sessionEntry struct {
	sess *noise.Session
	peer *peerState
}

type pendingHS struct {
	hs      *noise.HandshakeState
	peer    *peerState
	started time.Time
}

type peerState struct {
	id      identity.NodeID
	static  identity.PublicKey
	pairKey [32]byte
	vip     netip.Addr
	name    string
	online  bool
	gateway bool

	candidates []netip.AddrPort // endpoints from the netmap
	direct     netip.AddrPort   // active direct endpoint (zero => relay)
	lastPong   time.Time
	lastPing   time.Time
	pingTx     uint64
	pingSent   time.Time
	rtt        time.Duration
	lastDisco  time.Time // last discovery round

	session  *noise.Session
	queue    [][]byte
	lastHS   time.Time
	localIdx uint32 // index of in-flight handshake we initiated

	lastReport string // last path state sent to the control server
}

// Engine is the node data-plane engine.
type Engine struct {
	cfg  Config
	log  *slog.Logger
	dev  tunio.Device
	conn *net.UDPConn
	self identity.NodeID

	mu         sync.Mutex
	peersByID  map[identity.NodeID]*peerState
	peersByVIP map[netip.Addr]*peerState
	sessions   map[uint32]*sessionEntry
	handshakes map[uint32]*pendingHS
	// lastInitTS tracks the newest initiation timestamp accepted per peer
	// static key, to reject replayed initiations.
	lastInitTS map[identity.PublicKey]noise.Timestamp

	selfVIP   netip.Addr
	cidr      netip.Prefix
	gatewayID string
	relayAddr netip.AddrPort
	relayName string // unresolved host:port from the netmap
	// Relay health: a bind is confirmed by a BindOK; if confirmations stop
	// arriving the relay is considered unreachable again.
	bindSince     time.Time // first bind attempt for the current relay addr
	lastBindOK    time.Time
	lastRelayWarn time.Time
	observedEP    netip.AddrPort
	lastEPs       string // last endpoint set sent to control
	exitWanted    bool
	exitActive    bool
	natActive     bool
	controlIPs    []netip.Addr // pinned when exit mode is enabled

	closed chan struct{}
}

// New creates an Engine and binds its UDP socket.
func New(cfg Config) (*Engine, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.NetCfg == nil {
		cfg.NetCfg = NoopConfigurator{}
	}
	if cfg.MTU <= 0 {
		cfg.MTU = tunio.DefaultMTU
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.UDPPort})
	if err != nil {
		return nil, fmt.Errorf("binding UDP socket: %w", err)
	}
	e := &Engine{
		cfg:        cfg,
		log:        cfg.Log,
		dev:        cfg.Device,
		conn:       conn,
		self:       cfg.Identity.NodeID,
		peersByID:  map[identity.NodeID]*peerState{},
		peersByVIP: map[netip.Addr]*peerState{},
		sessions:   map[uint32]*sessionEntry{},
		handshakes: map[uint32]*pendingHS{},
		lastInitTS: map[identity.PublicKey]noise.Timestamp{},
		closed:     make(chan struct{}),
	}
	return e, nil
}

// LocalPort returns the engine's UDP port.
func (e *Engine) LocalPort() int {
	return e.conn.LocalAddr().(*net.UDPAddr).Port
}

// SetControlIPs records the control/relay server addresses that must bypass
// the tunnel in exit mode.
func (e *Engine) SetControlIPs(ips []netip.Addr) {
	e.mu.Lock()
	e.controlIPs = ips
	e.mu.Unlock()
}

// Run starts the engine loops and blocks until ctx is done or a fatal error
// occurs.
func (e *Engine) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- e.tunLoop() }()
	go func() { errCh <- e.udpLoop() }()
	go e.timerLoop(ctx)

	select {
	case <-ctx.Done():
		e.shutdown()
		return ctx.Err()
	case err := <-errCh:
		e.shutdown()
		return err
	}
}

func (e *Engine) shutdown() {
	select {
	case <-e.closed:
		return
	default:
		close(e.closed)
	}
	e.conn.Close()
	e.dev.Close()
	e.cfg.NetCfg.DisableExit()
	e.cfg.NetCfg.DisableGatewayNAT()
}

// ---- TUN -> network ----

func (e *Engine) tunLoop() error {
	buf := make([]byte, 65536)
	for {
		n, err := e.dev.ReadPacket(buf)
		if err != nil {
			select {
			case <-e.closed:
				return nil
			default:
				return fmt.Errorf("tun read: %w", err)
			}
		}
		pkt := buf[:n]
		dst, ok := ipv4Dst(pkt)
		if !ok {
			continue // non-IPv4 (e.g. IPv6 ND) — the overlay is IPv4-only
		}
		e.routePacket(pkt, dst)
	}
}

// routePacket picks the peer for an outgoing IP packet.
func (e *Engine) routePacket(pkt []byte, dst netip.Addr) {
	e.mu.Lock()
	peer := e.peersByVIP[dst]
	if peer == nil {
		if dst.IsMulticast() || dst == e.selfVIP {
			e.mu.Unlock()
			return
		}
		if !e.cidr.Contains(dst) && e.gatewayID != "" && e.gatewayID != e.self.String() {
			// Internet-bound packet: send to the passthrough gateway.
			if gwID, err := identity.ParseNodeID(e.gatewayID); err == nil {
				peer = e.peersByID[gwID]
			}
		}
	}
	e.mu.Unlock()
	if peer == nil {
		return
	}
	e.sendToPeer(peer, pkt)
}

// sendToPeer encrypts and transmits one IP packet to a peer, queueing it and
// starting a handshake when no session exists yet.
func (e *Engine) sendToPeer(peer *peerState, pkt []byte) {
	e.mu.Lock()
	sess := peer.session
	needHS := sess == nil || (sess.Initiator && sess.Age() > rekeyInterval)
	if sess == nil {
		if len(peer.queue) < maxQueuedPackets {
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			peer.queue = append(peer.queue, cp)
		}
	}
	e.mu.Unlock()

	if needHS {
		e.startHandshake(peer)
	}
	if sess == nil {
		e.startDiscovery(peer)
		return
	}
	sealed := sess.Seal(pkt)
	out := make([]byte, 0, 1+len(sealed))
	out = append(out, proto.TypeTransport)
	out = append(out, sealed...)
	e.sendRaw(peer, out)
}

// sendRaw transmits an already-framed data-plane packet via the peer's best
// path: the direct endpoint if one is established, otherwise the relay.
func (e *Engine) sendRaw(peer *peerState, framed []byte) {
	e.mu.Lock()
	direct := peer.direct
	relayAddr := e.relayAddr
	e.mu.Unlock()

	if direct.IsValid() {
		e.conn.WriteToUDPAddrPort(framed, direct)
		return
	}
	if relayAddr.IsValid() {
		e.conn.WriteToUDPAddrPort(proto.EncodeRelaySend(peer.id, framed), relayAddr)
	}
}

// ---- handshakes ----

func (e *Engine) startHandshake(peer *peerState) {
	e.mu.Lock()
	if time.Since(peer.lastHS) < handshakeRetry {
		e.mu.Unlock()
		return
	}
	peer.lastHS = time.Now()
	static := peer.static
	e.mu.Unlock()

	idx := noise.NewIndex()
	msg, hs, err := noise.NewInitiation(e.cfg.Identity, static, idx)
	if err != nil {
		e.log.Warn("handshake init failed", "peer", peer.id, "err", err)
		return
	}
	e.mu.Lock()
	peer.localIdx = idx
	e.handshakes[idx] = &pendingHS{hs: hs, peer: peer, started: time.Now()}
	e.mu.Unlock()

	out := append([]byte{proto.TypeInitiation}, msg.Marshal()...)
	e.sendRaw(peer, out)
	e.log.Debug("sent handshake initiation", "peer", peer.id)
}

// handleInitiation processes an incoming handshake initiation. reply sends
// a framed packet back along the path the initiation arrived on.
func (e *Engine) handleInitiation(payload []byte, reply func([]byte)) {
	msg, err := noise.UnmarshalInitiation(payload)
	if err != nil {
		return
	}
	remoteStatic, ts, hs, err := noise.ConsumeInitiation(e.cfg.Identity, msg)
	if err != nil {
		return
	}
	e.mu.Lock()
	peer := e.peersByID[remoteStatic.ID()]
	if peer == nil {
		e.mu.Unlock()
		return // not a member of our network
	}
	if last, ok := e.lastInitTS[remoteStatic]; ok && !ts.After(last) {
		e.mu.Unlock()
		return // replayed or out-of-order initiation
	}
	e.lastInitTS[remoteStatic] = ts
	e.mu.Unlock()

	idx := noise.NewIndex()
	resp, sess, err := hs.CreateResponse(idx)
	if err != nil {
		return
	}
	e.installSession(peer, idx, sess)
	reply(append([]byte{proto.TypeResponse}, resp.Marshal()...))
	e.log.Debug("accepted handshake", "peer", peer.id)
}

func (e *Engine) handleResponse(payload []byte) {
	msg, err := noise.UnmarshalResponse(payload)
	if err != nil {
		return
	}
	e.mu.Lock()
	pending := e.handshakes[msg.ReceiverIndex]
	if pending != nil {
		delete(e.handshakes, msg.ReceiverIndex)
	}
	e.mu.Unlock()
	if pending == nil {
		return
	}
	sess, err := pending.hs.ConsumeResponse(msg)
	if err != nil {
		return
	}
	e.installSession(pending.peer, msg.ReceiverIndex, sess)
	e.log.Debug("handshake complete", "peer", pending.peer.id)
	e.flushQueue(pending.peer)
}

func (e *Engine) installSession(peer *peerState, localIdx uint32, sess *noise.Session) {
	e.mu.Lock()
	peer.session = sess
	e.sessions[localIdx] = &sessionEntry{sess: sess, peer: peer}
	e.mu.Unlock()
	e.reportPath(peer)
}

func (e *Engine) flushQueue(peer *peerState) {
	e.mu.Lock()
	queue := peer.queue
	peer.queue = nil
	e.mu.Unlock()
	for _, pkt := range queue {
		e.sendToPeer(peer, pkt)
	}
}

// ---- network -> TUN ----

func (e *Engine) udpLoop() error {
	buf := make([]byte, 65536)
	for {
		n, raddr, err := e.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-e.closed:
				return nil
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				continue
			}
			return fmt.Errorf("udp read: %w", err)
		}
		e.handleUDP(buf[:n], unmap(raddr))
	}
}

func (e *Engine) handleUDP(pkt []byte, from netip.AddrPort) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] {
	case proto.TypeInitiation:
		e.handleInitiation(pkt[1:], func(resp []byte) {
			e.conn.WriteToUDPAddrPort(resp, from)
		})
	case proto.TypeResponse:
		e.handleResponse(pkt[1:])
	case proto.TypeTransport:
		e.handleTransport(pkt[1:], from, identity.NodeID{})
	case proto.TypeDisco:
		e.handleDisco(pkt[1:], from, false)
	case proto.TypeRelayRecv:
		src, inner, err := proto.DecodeRelayRecv(pkt[1:])
		if err != nil || len(inner) < 1 {
			return
		}
		switch inner[0] {
		case proto.TypeInitiation:
			e.handleInitiation(inner[1:], func(resp []byte) {
				e.mu.Lock()
				relayAddr := e.relayAddr
				e.mu.Unlock()
				if relayAddr.IsValid() {
					e.conn.WriteToUDPAddrPort(proto.EncodeRelaySend(src, resp), relayAddr)
				}
			})
		case proto.TypeResponse:
			e.handleResponse(inner[1:])
		case proto.TypeTransport:
			e.handleTransport(inner[1:], netip.AddrPort{}, src)
		case proto.TypeDisco:
			e.handleDisco(inner[1:], netip.AddrPort{}, true)
		}
	case proto.TypeRelayBindOK:
		e.mu.Lock()
		e.lastBindOK = time.Now()
		e.mu.Unlock()
	case proto.TypeRelayBindErr:
		e.mu.Lock()
		e.lastBindOK = time.Time{}
		e.mu.Unlock()
		e.log.Warn("relay rejected our bind (stale session token?) — try re-joining the network")
	case proto.TypeWhoAmIResp:
		_, observed, err := proto.DecodeWhoAmIResp(pkt[1:])
		if err != nil {
			return
		}
		e.setObservedEndpoint(observed)
	}
}

// handleTransport decrypts a transport packet and writes the inner IP packet
// to the TUN device (or forwards it, on a gateway).
func (e *Engine) handleTransport(payload []byte, from netip.AddrPort, viaRelaySrc identity.NodeID) {
	idx, err := noise.ReceiverIndex(payload)
	if err != nil {
		return
	}
	e.mu.Lock()
	entry := e.sessions[idx]
	e.mu.Unlock()
	if entry == nil {
		return
	}
	inner, err := entry.sess.Open(payload)
	if err != nil {
		return
	}
	peer := entry.peer

	e.mu.Lock()
	peer.lastPong = time.Now() // any authenticated traffic proves liveness
	selfVIP, cidr := e.selfVIP, e.cidr
	isGatewaySelf := e.gatewayID == e.self.String()
	e.mu.Unlock()

	src, dst, ok := ipv4SrcDst(inner)
	if !ok {
		return
	}
	// Anti-spoofing: a peer may only send packets from its own virtual IP —
	// unless it is the network gateway, which forwards NAT return traffic
	// with external source addresses.
	if src != peer.vip && !peer.gateway {
		return
	}
	// Destination must be us, unless we are the gateway forwarding
	// internet-bound traffic into the OS NAT.
	if dst != selfVIP && !(isGatewaySelf && !cidr.Contains(dst)) {
		return
	}
	e.dev.WritePacket(inner)
}

// ---- helpers ----

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func ipv4Dst(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[16:20])), true
}

func ipv4SrcDst(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), true
}
