package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/noise"
	"github.com/yeungalan/vvvlan/internal/proto"
)

// ---- disco (path probing) ----
//
// Disco messages are small encrypted probes. A ping sent to a candidate
// endpoint that comes back as a pong proves the path works in both
// directions; the engine then switches the peer from relay to that direct
// endpoint. Probes are encrypted with a per-pair key derived from the two
// nodes' static keys, and are prefixed with the sender's node ID in the
// clear so the receiver knows which pair key to try:
//
//	[TypeDisco][sender node id 16][sealed DiscoMessage]

func (e *Engine) sendDisco(peer *peerState, msg *proto.DiscoMessage, to netip.AddrPort, viaRelay bool) {
	sealed, err := noise.SealDisco(&peer.pairKey, msg.Marshal())
	if err != nil {
		return
	}
	out := make([]byte, 0, 17+len(sealed))
	out = append(out, proto.TypeDisco)
	out = append(out, e.self[:]...)
	out = append(out, sealed...)

	if viaRelay {
		e.mu.Lock()
		relayAddr := e.relayAddr
		e.mu.Unlock()
		if relayAddr.IsValid() {
			e.conn.WriteToUDPAddrPort(proto.EncodeRelaySend(peer.id, out), relayAddr)
		}
		return
	}
	e.conn.WriteToUDPAddrPort(out, to)
}

func (e *Engine) handleDisco(payload []byte, from netip.AddrPort, viaRelay bool) {
	if len(payload) < 16 {
		return
	}
	var senderID identity.NodeID
	copy(senderID[:], payload[:16])
	e.mu.Lock()
	peer := e.peersByID[senderID]
	e.mu.Unlock()
	if peer == nil {
		return
	}
	plain, err := noise.OpenDisco(&peer.pairKey, payload[16:])
	if err != nil {
		return
	}
	msg, err := proto.UnmarshalDisco(plain)
	if err != nil || msg.Sender != senderID {
		return
	}

	switch msg.Kind {
	case proto.DiscoPing:
		pong := &proto.DiscoMessage{
			Kind:     proto.DiscoPong,
			Sender:   e.self,
			TxID:     msg.TxID,
			Observed: from,
		}
		if viaRelay {
			e.sendDisco(peer, pong, netip.AddrPort{}, true)
			return
		}
		e.sendDisco(peer, pong, from, false)
		// A direct ping proves the peer can reach us at this address pair;
		// if we don't have a direct path yet, probe back immediately so
		// both sides converge without waiting for the next discovery round.
		e.mu.Lock()
		probeBack := !peer.direct.IsValid() && time.Since(peer.lastPing) > time.Second
		e.mu.Unlock()
		if probeBack {
			e.probeEndpoints(peer, []netip.AddrPort{from})
		}

	case proto.DiscoPong:
		if viaRelay || !from.IsValid() {
			return // only direct pongs prove a direct path
		}
		e.mu.Lock()
		if e.cidr.IsValid() && e.cidr.Contains(from.Addr()) {
			// A "direct" path via an overlay address is the tunnel itself.
			e.mu.Unlock()
			return
		}
		if msg.TxID == peer.pingTx {
			peer.rtt = time.Since(peer.pingSent)
		}
		peer.lastPong = time.Now()
		changed := peer.direct != from
		if changed {
			peer.direct = from
			e.log.Info("direct path established", "peer", peer.name, "endpoint", from)
		}
		exitOn := e.exitActive
		e.mu.Unlock()
		if changed {
			if exitOn {
				e.cfg.NetCfg.Pin(from.Addr())
			}
			e.reportPath(peer)
		}
	}
}

// startDiscovery probes all candidate endpoints of a peer and asks the
// control server to have the peer probe us back (simultaneous hole punch).
func (e *Engine) startDiscovery(peer *peerState) {
	e.mu.Lock()
	if time.Since(peer.lastDisco) < discoRetryPeriod && !peer.direct.IsValid() {
		// A discovery round is already in flight.
		e.mu.Unlock()
		return
	}
	if peer.direct.IsValid() {
		e.mu.Unlock()
		return
	}
	peer.lastDisco = time.Now()
	candidates := append([]netip.AddrPort(nil), peer.candidates...)
	e.mu.Unlock()

	e.probeEndpoints(peer, candidates)
	if e.cfg.AskPunch != nil {
		e.cfg.AskPunch(peer.id.String())
	}
}

// probeEndpoints sends disco pings to the given candidate endpoints.
func (e *Engine) probeEndpoints(peer *peerState, candidates []netip.AddrPort) {
	tx := randUint64()
	e.mu.Lock()
	peer.pingTx = tx
	peer.pingSent = time.Now()
	peer.lastPing = time.Now()
	cidr := e.cidr
	e.mu.Unlock()
	msg := &proto.DiscoMessage{Kind: proto.DiscoPing, Sender: e.self, TxID: tx}
	for _, ep := range candidates {
		if !ep.Addr().Is4() && !ep.Addr().Is4In6() {
			continue
		}
		// Overlay addresses would route probes back into the tunnel.
		if cidr.IsValid() && cidr.Contains(ep.Addr().Unmap()) {
			continue
		}
		e.sendDisco(peer, msg, ep, false)
	}
}

// HandlePunch reacts to a control-server punch request: a peer is probing
// toward us, so probe back to open our NAT mapping toward it.
func (e *Engine) HandlePunch(req *proto.PunchRequest) {
	id, err := identity.ParseNodeID(req.FromNodeID)
	if err != nil {
		return
	}
	e.mu.Lock()
	peer := e.peersByID[id]
	e.mu.Unlock()
	if peer == nil {
		return
	}
	var eps []netip.AddrPort
	for _, s := range req.Endpoints {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			eps = append(eps, ap)
		}
	}
	e.log.Debug("punch request", "peer", peer.name, "endpoints", len(eps))
	e.probeEndpoints(peer, eps)
}

// ---- timers ----

func (e *Engine) timerLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	lastBind := time.Time{}
	lastWho := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.closed:
			return
		case <-ticker.C:
		}
		now := time.Now()
		if now.Sub(lastBind) >= relayBindPeriod {
			lastBind = now
			e.bindRelay()
		}
		if now.Sub(lastWho) >= whoAmIPeriod {
			lastWho = now
			e.refreshEndpoints()
		}
		e.maintainPeers()
		e.pruneSessions()
	}
}

// bindRelay (re)registers our address mapping with the relay server and
// warns when the relay has stopped confirming our binds (unreachable UDP
// port is the most common deployment problem).
func (e *Engine) bindRelay() {
	e.mu.Lock()
	relayAddr := e.relayAddr
	if !relayAddr.IsValid() {
		e.mu.Unlock()
		return
	}
	now := time.Now()
	if e.bindSince.IsZero() {
		e.bindSince = now
	}
	warn := !e.relayHealthyLocked() &&
		now.Sub(e.bindSince) > 30*time.Second &&
		now.Sub(e.lastRelayWarn) > time.Minute
	if warn {
		e.lastRelayWarn = now
	}
	e.mu.Unlock()
	if warn {
		e.log.Warn("relay server is not responding — peers without a direct path will be unreachable; "+
			"check that the relay UDP port is reachable (server firewall rule, router port forwarding)",
			"relay", relayAddr)
	}
	bind := proto.RelayBind{NodeID: e.self, SessionToken: e.cfg.SessionToken}
	e.conn.WriteToUDPAddrPort(bind.Marshal(), relayAddr)
	// The relay socket doubles as our endpoint reflector.
	e.conn.WriteToUDPAddrPort(proto.EncodeWhoAmI(randUint64()), relayAddr)
}

// relayHealthyLocked reports whether the relay confirmed a bind recently.
// Callers must hold e.mu.
func (e *Engine) relayHealthyLocked() bool {
	return !e.lastBindOK.IsZero() && time.Since(e.lastBindOK) < 90*time.Second
}

func (e *Engine) setObservedEndpoint(observed netip.AddrPort) {
	e.mu.Lock()
	changed := e.observedEP != observed
	e.observedEP = observed
	e.mu.Unlock()
	if changed {
		e.log.Info("public endpoint discovered", "endpoint", observed)
		e.refreshEndpoints()
	}
}

// refreshEndpoints collects our candidate endpoints (local interface
// addresses plus the reflector-observed public endpoint) and reports them to
// the control server when they change.
func (e *Engine) refreshEndpoints() {
	port := uint16(e.LocalPort())
	e.mu.Lock()
	cidr := e.cidr
	e.mu.Unlock()
	var eps []string
	for _, addr := range localIPv4Addrs() {
		// Never advertise our own overlay address: peers reaching us
		// through it would tunnel the tunnel.
		if cidr.IsValid() && cidr.Contains(addr) {
			continue
		}
		eps = append(eps, netip.AddrPortFrom(addr, port).String())
	}
	e.mu.Lock()
	if e.observedEP.IsValid() {
		eps = append(eps, e.observedEP.String())
	}
	sort.Strings(eps)
	joined := strings.Join(eps, ",")
	changed := joined != e.lastEPs
	e.lastEPs = joined
	e.mu.Unlock()
	if changed && e.cfg.ReportEndpoints != nil {
		e.cfg.ReportEndpoints(eps)
	}
}

func localIPv4Addrs() []netip.Addr {
	var out []netip.Addr
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP.To4())
			if !ok || !addr.Is4() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, addr)
		}
	}
	return out
}

// maintainPeers runs per-peer upkeep: keepalives on direct paths, fallback
// to relay when a direct path goes stale, and discovery retries for peers
// with queued traffic.
func (e *Engine) maintainPeers() {
	e.mu.Lock()
	peers := make([]*peerState, 0, len(e.peersByID))
	for _, p := range e.peersByID {
		peers = append(peers, p)
	}
	e.mu.Unlock()

	now := time.Now()
	for _, p := range peers {
		e.mu.Lock()
		hasDirect := p.direct.IsValid()
		stale := hasDirect && now.Sub(p.lastPong) > directStaleAfter
		needKeepalive := hasDirect && !stale && now.Sub(p.lastPing) >= discoKeepalive
		hasSession := p.session != nil
		hasQueue := len(p.queue) > 0
		direct := p.direct
		online := p.online
		if stale {
			e.log.Info("direct path lost, falling back to relay", "peer", p.name)
			p.direct = netip.AddrPort{}
		}
		e.mu.Unlock()

		switch {
		case stale:
			e.reportPath(p)
			if online {
				e.startDiscovery(p)
			}
		case needKeepalive:
			tx := randUint64()
			e.mu.Lock()
			p.pingTx = tx
			p.pingSent = now
			p.lastPing = now
			e.mu.Unlock()
			e.sendDisco(p, &proto.DiscoMessage{Kind: proto.DiscoPing, Sender: e.self, TxID: tx}, direct, false)
		case hasSession && !hasDirect && online:
			// Keep trying to upgrade relayed peers to a direct path.
			e.startDiscovery(p)
		}
		if hasQueue && !hasSession {
			e.startHandshake(p)
		}
		e.reportPath(p) // no-op unless the path state changed
	}
}

// pruneSessions drops session entries that were replaced long ago and
// abandoned handshakes.
func (e *Engine) pruneSessions() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for idx, entry := range e.sessions {
		if entry.sess.Age() > sessionMaxAge && entry.peer.session != entry.sess {
			delete(e.sessions, idx)
		}
	}
	for idx, hs := range e.handshakes {
		if time.Since(hs.started) > 30*time.Second {
			delete(e.handshakes, idx)
		}
	}
}

// reportPath publishes the peer's current path state (direct endpoint or
// relay) to the control server, but only when it changed since the last
// report, so it is cheap to call from periodic maintenance.
func (e *Engine) reportPath(peer *peerState) {
	if e.cfg.ReportPath == nil {
		return
	}
	e.mu.Lock()
	rep := proto.PathReport{
		PeerNodeID: peer.id.String(),
		LatencyMS:  peer.rtt.Milliseconds(),
	}
	var state string
	switch {
	case peer.direct.IsValid():
		rep.Direct = true
		rep.Endpoint = peer.direct.String()
		state = "direct:" + rep.Endpoint
	case peer.session != nil:
		state = "relay"
	default:
		// No tunnel yet — nothing to report.
		e.mu.Unlock()
		return
	}
	changed := state != peer.lastReport
	peer.lastReport = state
	e.mu.Unlock()
	if changed {
		e.cfg.ReportPath(rep)
	}
}

func randUint64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}
