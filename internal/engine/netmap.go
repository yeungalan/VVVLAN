package engine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/noise"
	"github.com/yeungalan/vvvlan/internal/proto"
	"github.com/yeungalan/vvvlan/internal/usernat"
)

// UpdateNetMap reconciles the engine with a netmap pushed by the control
// server: peer set, virtual IP/interface config, relay address, gateway
// role, and exit-node routing.
func (e *Engine) UpdateNetMap(nm *proto.NetMap) {
	cidr, err := netip.ParsePrefix(nm.CIDR)
	if err != nil {
		e.log.Error("netmap has invalid CIDR", "cidr", nm.CIDR, "err", err)
		return
	}
	selfVIP, err := netip.ParseAddr(nm.Self.VirtualIP)
	if err != nil {
		e.log.Error("netmap has invalid self IP", "ip", nm.Self.VirtualIP, "err", err)
		return
	}

	e.mu.Lock()
	vipChanged := e.selfVIP != selfVIP || e.cidr != cidr
	e.selfVIP = selfVIP
	e.cidr = cidr
	e.gatewayID = nm.GatewayNodeID
	relayName := nm.RelayAddr
	relayChanged := relayName != e.relayName
	e.relayName = relayName

	// Reconcile peers.
	seen := map[identity.NodeID]bool{}
	for _, p := range nm.Peers {
		pub, err := identity.ParsePublicKey(p.PublicKey)
		if err != nil {
			continue
		}
		id := pub.ID()
		seen[id] = true
		vip, err := netip.ParseAddr(p.VirtualIP)
		if err != nil {
			continue
		}
		ps := e.peersByID[id]
		if ps == nil {
			pairKey, err := noise.PairKey(e.cfg.Identity.PrivateKey, pub)
			if err != nil {
				continue
			}
			ps = &peerState{id: id, static: pub, pairKey: pairKey}
			e.peersByID[id] = ps
		}
		if ps.vip != vip {
			delete(e.peersByVIP, ps.vip)
			ps.vip = vip
			e.peersByVIP[vip] = ps
		}
		ps.name = p.Name
		ps.online = p.Online
		ps.gateway = p.IsGateway
		ps.candidates = ps.candidates[:0]
		for _, s := range p.Endpoints {
			if ap, err := netip.ParseAddrPort(s); err == nil {
				ps.candidates = append(ps.candidates, ap)
			}
		}
	}
	for id, ps := range e.peersByID {
		if !seen[id] {
			delete(e.peersByID, id)
			delete(e.peersByVIP, ps.vip)
			if ps.session != nil {
				for idx, entry := range e.sessions {
					if entry.peer == ps {
						delete(e.sessions, idx)
					}
				}
			}
		}
	}
	isGateway := nm.GatewayNodeID == e.self.String()
	natActive := e.natActive
	natRetryOK := time.Now().After(e.natRetryAt)
	e.mu.Unlock()

	if vipChanged {
		bits := cidr.Bits()
		if err := e.cfg.NetCfg.ConfigureInterface(netip.PrefixFrom(selfVIP, bits), e.cfg.MTU); err != nil {
			e.log.Error("configuring interface failed", "err", err)
		} else {
			e.log.Info("interface configured", "ip", selfVIP, "cidr", cidr)
		}
	}
	if relayChanged {
		e.resolveRelay(relayName)
		e.bindRelay()
	}

	// Gateway role: turn NAT on/off to match the netmap. Netmaps arrive
	// frequently, so failed attempts are retried on a cool-down instead of
	// on every update.
	switch {
	case isGateway && !natActive && natRetryOK:
		if err := e.enableGatewayNAT(cidr); err != nil {
			e.log.Error("enabling gateway NAT failed; retrying in 5m", "err", err)
			e.mu.Lock()
			e.natRetryAt = time.Now().Add(5 * time.Minute)
			e.mu.Unlock()
		}
	case !isGateway:
		e.disableGatewayNAT()
	}

	e.reconcileExit()
	e.refreshEndpoints()
}

// enableGatewayNAT makes this node the internet gateway. OS-level NAT is
// preferred (kernel-speed forwarding); when it is unavailable — Windows
// Home without WinNAT, macOS without a pf rule — or when UserspaceNAT is
// set, gateway traffic is NATed in userspace with an in-process TCP/IP
// stack, the way Tailscale's netstack mode does it. Userspace mode forwards
// TCP and UDP (not ICMP) and needs no OS configuration at all.
func (e *Engine) enableGatewayNAT(cidr netip.Prefix) error {
	if !e.cfg.UserspaceNAT && e.cfg.NetCfg.KernelNATSupported() {
		if err := e.cfg.NetCfg.EnableGatewayNAT(cidr); err == nil {
			e.mu.Lock()
			e.natActive = true
			e.natMode = "kernel"
			e.mu.Unlock()
			e.log.Info("this node is now the internet gateway for the network", "nat", "kernel")
			return nil
		} else {
			e.log.Warn("OS gateway NAT unavailable, falling back to userspace NAT (TCP/UDP only)", "err", err)
		}
	}
	unat, err := usernat.New(e.cfg.MTU, e.emitFromNAT, e.log)
	if err != nil {
		return fmt.Errorf("starting userspace NAT: %w", err)
	}
	e.mu.Lock()
	e.unat = unat
	e.natActive = true
	e.natMode = "userspace"
	e.mu.Unlock()
	e.log.Info("this node is now the internet gateway for the network", "nat", "userspace")
	return nil
}

func (e *Engine) disableGatewayNAT() {
	e.mu.Lock()
	wasActive := e.natActive
	mode := e.natMode
	unat := e.unat
	e.unat = nil
	e.natActive = false
	e.natMode = ""
	e.natRetryAt = time.Time{} // re-designation retries immediately
	e.mu.Unlock()
	if !wasActive {
		return
	}
	if unat != nil {
		unat.Close()
	}
	if mode == "kernel" {
		if err := e.cfg.NetCfg.DisableGatewayNAT(); err != nil {
			e.log.Warn("disabling gateway NAT failed", "err", err)
		}
	}
	e.log.Info("gateway role removed")
}

// emitFromNAT delivers packets synthesized by the userspace NAT (responses
// for overlay clients) back through the encrypted tunnel.
func (e *Engine) emitFromNAT(pkt []byte) {
	dst, ok := ipv4Dst(pkt)
	if !ok {
		return
	}
	e.mu.Lock()
	peer := e.peersByVIP[dst]
	e.mu.Unlock()
	if peer == nil {
		return
	}
	e.sendToPeer(peer, pkt)
}

// resolveRelay resolves the relay's host:port (DNS allowed) to an address.
func (e *Engine) resolveRelay(hostport string) {
	if hostport == "" {
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", hostport)
	if err != nil {
		e.log.Error("resolving relay address failed", "relay", hostport, "err", err)
		return
	}
	ap := unmap(udpAddr.AddrPort())
	e.mu.Lock()
	changed := e.relayAddr != ap
	e.relayAddr = ap
	if changed {
		e.bindSince = time.Time{}
		e.lastBindOK = time.Time{}
	}
	e.mu.Unlock()
	if changed {
		e.log.Info("using relay", "addr", ap)
	}
}

// SetExit enables or disables routing this node's internet traffic through
// the network's gateway node.
func (e *Engine) SetExit(on bool) error {
	e.mu.Lock()
	e.exitWanted = on
	gw := e.gatewayID
	self := e.self.String()
	e.mu.Unlock()
	if on {
		if gw == "" {
			return errors.New("network has no gateway node (set one in the admin UI)")
		}
		if gw == self {
			return errors.New("this node is the gateway itself")
		}
	}
	e.reconcileExit()
	e.mu.Lock()
	defer e.mu.Unlock()
	if on && !e.exitActive {
		return errors.New("failed to enable exit routes (see logs)")
	}
	return nil
}

// reconcileExit makes the OS routing state match the desired exit mode.
func (e *Engine) reconcileExit() {
	e.mu.Lock()
	want := e.exitWanted && e.gatewayID != "" && e.gatewayID != e.self.String()
	active := e.exitActive
	pins := append([]netip.Addr(nil), e.controlIPs...)
	if e.relayAddr.IsValid() {
		pins = append(pins, e.relayAddr.Addr())
	}
	for _, p := range e.peersByID {
		if p.direct.IsValid() {
			pins = append(pins, p.direct.Addr())
		}
	}
	e.mu.Unlock()

	switch {
	case want && !active:
		if err := e.cfg.NetCfg.EnableExit(pins); err != nil {
			e.log.Error("enabling internet passthrough failed", "err", err)
			return
		}
		e.mu.Lock()
		e.exitActive = true
		e.mu.Unlock()
	case !want && active:
		if err := e.cfg.NetCfg.DisableExit(); err != nil {
			e.log.Warn("disabling internet passthrough failed", "err", err)
		}
		e.mu.Lock()
		e.exitActive = false
		e.mu.Unlock()
	}
}

// PeerStatus is a snapshot of one peer's connectivity for the local API.
type PeerStatus struct {
	NodeID    string        `json:"node_id"`
	Name      string        `json:"name"`
	VirtualIP string        `json:"virtual_ip"`
	Online    bool          `json:"online"`
	IsGateway bool          `json:"is_gateway"`
	Direct    bool          `json:"direct"`
	Endpoint  string        `json:"endpoint,omitempty"`
	RTT       time.Duration `json:"rtt_ns"`
	HasTunnel bool          `json:"has_tunnel"`
}

// Status is an engine snapshot for the local API / CLI.
type Status struct {
	NodeID      string         `json:"node_id"`
	VirtualIP   string         `json:"virtual_ip"`
	CIDR        string         `json:"cidr"`
	RelayAddr   string         `json:"relay_addr"`
	RelayBound  bool           `json:"relay_bound"`
	PublicAddr  string         `json:"public_addr,omitempty"`
	ExitEnabled bool           `json:"exit_enabled"`
	IsGateway   bool           `json:"is_gateway"`
	NATMode     string         `json:"nat_mode,omitempty"` // kernel|userspace when gateway
	NATStats    *usernat.Stats `json:"nat_stats,omitempty"`
	Peers       []PeerStatus   `json:"peers"`
}

// Snapshot returns the current engine status.
func (e *Engine) Snapshot() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{
		NodeID:      e.self.String(),
		CIDR:        prefixString(e.cidr),
		RelayBound:  e.relayHealthyLocked(),
		ExitEnabled: e.exitActive,
		IsGateway:   e.gatewayID == e.self.String(),
		NATMode:     e.natMode,
	}
	if e.selfVIP.IsValid() {
		st.VirtualIP = e.selfVIP.String()
	}
	if e.relayAddr.IsValid() {
		st.RelayAddr = e.relayAddr.String()
	}
	if e.observedEP.IsValid() {
		st.PublicAddr = e.observedEP.String()
	}
	if e.unat != nil {
		stats := e.unat.Stats()
		st.NATStats = &stats
	}
	for _, p := range e.peersByID {
		ps := PeerStatus{
			NodeID:    p.id.String(),
			Name:      p.name,
			VirtualIP: p.vip.String(),
			Online:    p.online,
			IsGateway: p.gateway,
			Direct:    p.direct.IsValid(),
			RTT:       p.rtt,
			HasTunnel: p.session != nil,
		}
		if p.direct.IsValid() {
			ps.Endpoint = p.direct.String()
		}
		st.Peers = append(st.Peers, ps)
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].VirtualIP < st.Peers[j].VirtualIP })
	return st
}

func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

// Ping sends a disco probe to a peer by virtual IP (used by `vvvland ping`).
func (e *Engine) Ping(vip netip.Addr) (string, error) {
	e.mu.Lock()
	peer := e.peersByVIP[vip]
	e.mu.Unlock()
	if peer == nil {
		return "", fmt.Errorf("no peer with virtual IP %v", vip)
	}
	e.startDiscovery(peer)
	return peer.name, nil
}
