// Package usernat implements userspace NAT for internet passthrough, the
// way Tailscale does it on platforms without configurable OS NAT: IP packets
// arriving over the overlay are injected into an in-process TCP/IP stack
// (gVisor netstack); the stack terminates each TCP/UDP flow and the flow is
// re-dialed as an ordinary host socket, so return traffic is synthesized
// back toward the overlay client. No kernel forwarding, no iptables/NetNat/
// pf, and no privileges beyond what the agent already has.
//
// Limitations: only TCP and UDP are forwarded (ICMP ping through the
// gateway does not work in userspace mode).
package usernat

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	// maxInFlightTCP bounds concurrent half-open TCP connects.
	maxInFlightTCP = 1024
	// udpIdleTimeout ends the proxying of a UDP flow after inactivity.
	udpIdleTimeout = 90 * time.Second
	dialTimeout    = 15 * time.Second
)

// NAT is a userspace NAT instance.
type NAT struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	log    *slog.Logger
	cancel context.CancelFunc

	tcpFlows    atomic.Int64
	udpFlows    atomic.Int64
	dialErrors  atomic.Int64
	lastDialLog atomic.Int64 // unix seconds, rate-limits dial error logging
}

// Stats is a snapshot of NAT activity, used for diagnostics.
type Stats struct {
	TCPFlows   int64 `json:"tcp_flows"`
	UDPFlows   int64 `json:"udp_flows"`
	DialErrors int64 `json:"dial_errors"`
}

// Stats returns cumulative flow counters.
func (n *NAT) Stats() Stats {
	return Stats{
		TCPFlows:   n.tcpFlows.Load(),
		UDPFlows:   n.udpFlows.Load(),
		DialErrors: n.dialErrors.Load(),
	}
}

// noteDialError counts a failed outbound dial and logs it at most once per
// 10 seconds — a stream of these usually means the gateway host itself has
// no internet access or a firewall blocks outbound connections.
func (n *NAT) noteDialError(proto, dst string, err error) {
	n.dialErrors.Add(1)
	now := time.Now().Unix()
	last := n.lastDialLog.Load()
	if now-last >= 10 && n.lastDialLog.CompareAndSwap(last, now) {
		n.log.Warn("userspace NAT could not reach destination", "proto", proto, "dst", dst, "err", err,
			"total_dial_errors", n.dialErrors.Load())
	}
}

// New creates a userspace NAT. emit is called (from an internal goroutine)
// with every IP packet the NAT wants delivered back to overlay clients; the
// caller routes those to the right peer by destination address.
func New(mtu int, emit func(pkt []byte), log *slog.Logger) (*NAT, error) {
	return newNAT(mtu, emit, log, false)
}

// newNAT optionally allows flows to loopback destinations. Production NATs
// keep netstack's default martian filtering so overlay clients cannot reach
// services bound to the gateway's 127.0.0.1; tests use loopback servers as
// the stand-in "internet".
func newNAT(mtu int, emit func(pkt []byte), log *slog.Logger, allowLoopback bool) (*NAT, error) {
	ipv4Factory := ipv4.NewProtocol
	if allowLoopback {
		ipv4Factory = ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true})
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4Factory},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("usernat: creating NIC: %v", err)
	}
	// Accept packets for any destination (we are a router, not a host) and
	// allow responding from any source address.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("usernat: promiscuous mode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("usernat: spoofing mode: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	n := &NAT{stack: s, ep: ep, log: log}

	tcpFwd := tcp.NewForwarder(s, 0, maxInFlightTCP, n.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, n.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	go n.pump(ctx, emit)
	return n, nil
}

// pump delivers packets synthesized by netstack back to the overlay.
func (n *NAT) pump(ctx context.Context, emit func([]byte)) {
	for {
		pkt := n.ep.ReadContext(ctx)
		if pkt == nil {
			return // endpoint closed or ctx canceled
		}
		buf := pkt.ToBuffer()
		emit(buf.Flatten())
		buf.Release()
		pkt.DecRef()
	}
}

// InjectInbound feeds an internet-bound IPv4 packet from an overlay peer
// into the NAT.
func (n *NAT) InjectInbound(pkt []byte) {
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
	})
	n.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	pkb.DecRef()
}

// Close shuts the NAT down and aborts all proxied flows.
func (n *NAT) Close() {
	n.cancel()
	n.stack.Close()
	n.ep.Close()
}

func fullAddr(a tcpip.Address, port uint16) string {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return net.JoinHostPort(ip.String(), fmt.Sprint(port))
}

// handleTCP terminates an overlay TCP flow in netstack and splices it onto a
// real outbound connection to the original destination.
func (n *NAT) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	// LocalAddress is the flow's original destination (we are promiscuous).
	dst := fullAddr(id.LocalAddress, id.LocalPort)

	outbound, err := net.DialTimeout("tcp", dst, dialTimeout)
	if err != nil {
		n.noteDialError("tcp", dst, err)
		r.Complete(true) // send RST: destination unreachable
		return
	}
	n.tcpFlows.Add(1)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		outbound.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	inbound := gonet.NewTCPConn(&wq, ep)
	go splice(inbound, outbound)
}

// handleUDP proxies an overlay UDP flow to the original destination with an
// idle timeout.
func (n *NAT) handleUDP(r *udp.ForwarderRequest) (handled bool) {
	id := r.ID()
	dst := fullAddr(id.LocalAddress, id.LocalPort)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		return false
	}
	inbound := gonet.NewUDPConn(&wq, ep)
	outbound, err := net.Dial("udp", dst)
	if err != nil {
		n.noteDialError("udp", dst, err)
		inbound.Close()
		return true
	}
	n.udpFlows.Add(1)
	go spliceUDP(inbound, outbound)
	go spliceUDP(outbound, inbound)
	return true
}

// splice copies both directions of a TCP flow and closes both ends when
// either side finishes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}

// spliceUDP copies datagrams src->dst until the flow idles out.
func spliceUDP(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	buf := make([]byte, 65535)
	for {
		src.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		nr, err := src.Read(buf)
		if err != nil {
			return
		}
		if _, err := dst.Write(buf[:nr]); err != nil {
			return
		}
	}
}
