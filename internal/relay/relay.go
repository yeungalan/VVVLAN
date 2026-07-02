// Package relay implements the VVVLAN relay/bridge server: a UDP service
// that (1) reflects clients' public endpoints back to them (STUN-lite, used
// for NAT discovery), and (2) forwards encrypted data-plane packets between
// nodes that cannot reach each other directly. The relay never sees
// plaintext traffic; it forwards opaque noise-encrypted packets.
package relay

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/proto"
)

const (
	// bindTTL is how long a node's address mapping survives without a
	// refreshing RelayBind. Clients re-bind every 25s.
	bindTTL = 90 * time.Second

	maxPacket = 65535
)

// TokenValidator checks that a session token belongs to the given node.
// The control server supplies this so the relay only forwards for
// authenticated members.
type TokenValidator func(node identity.NodeID, sessionToken string) bool

type binding struct {
	addr     netip.AddrPort
	deadline time.Time
}

// Server is the relay server.
type Server struct {
	conn     *net.UDPConn
	validate TokenValidator
	log      *slog.Logger

	mu     sync.RWMutex
	byNode map[identity.NodeID]binding
	byAddr map[netip.AddrPort]identity.NodeID
}

// New creates a relay server listening on the given UDP address
// (e.g. ":41641").
func New(listen string, validate TokenValidator, log *slog.Logger) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		conn:     conn,
		validate: validate,
		log:      log,
		byNode:   make(map[identity.NodeID]binding),
		byAddr:   make(map[netip.AddrPort]identity.NodeID),
	}, nil
}

// LocalPort returns the UDP port the relay is bound to.
func (s *Server) LocalPort() int {
	return s.conn.LocalAddr().(*net.UDPAddr).Port
}

// Serve processes packets until the connection is closed.
func (s *Server) Serve() error {
	go s.expireLoop()
	buf := make([]byte, maxPacket)
	for {
		n, raddr, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		s.handle(buf[:n], unmap(raddr))
	}
}

// Close shuts the relay down.
func (s *Server) Close() error { return s.conn.Close() }

func (s *Server) handle(pkt []byte, from netip.AddrPort) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] {
	case proto.TypeWhoAmI:
		if len(pkt) < 9 {
			return
		}
		txid := be64(pkt[1:9])
		resp := proto.EncodeWhoAmIResp(txid, from)
		s.conn.WriteToUDPAddrPort(resp, from)

	case proto.TypeRelayBind:
		bind, err := proto.UnmarshalRelayBind(pkt[1:])
		if err != nil {
			return
		}
		if !s.validate(bind.NodeID, bind.SessionToken) {
			s.conn.WriteToUDPAddrPort([]byte{proto.TypeRelayBindErr}, from)
			return
		}
		s.mu.Lock()
		if old, ok := s.byNode[bind.NodeID]; ok && old.addr != from {
			delete(s.byAddr, old.addr)
		}
		s.byNode[bind.NodeID] = binding{addr: from, deadline: time.Now().Add(bindTTL)}
		s.byAddr[from] = bind.NodeID
		s.mu.Unlock()
		s.conn.WriteToUDPAddrPort([]byte{proto.TypeRelayBindOK}, from)

	case proto.TypeRelaySend:
		dst, inner, err := proto.DecodeRelaySend(pkt[1:])
		if err != nil {
			return
		}
		s.mu.RLock()
		src, srcBound := s.byAddr[from]
		dstBind, dstBound := s.byNode[dst]
		s.mu.RUnlock()
		if !srcBound || !dstBound {
			return // sender must be bound; unknown dst is dropped silently
		}
		out := proto.EncodeRelayRecv(src, inner)
		s.conn.WriteToUDPAddrPort(out, dstBind.addr)
	}
}

func (s *Server) expireLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, b := range s.byNode {
			if now.After(b.deadline) {
				delete(s.byNode, id)
				delete(s.byAddr, b.addr)
			}
		}
		s.mu.Unlock()
	}
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func be64(b []byte) uint64 {
	var v uint64
	for _, x := range b[:8] {
		v = v<<8 | uint64(x)
	}
	return v
}

// ConstantTimeTokenEq compares tokens without leaking length-independent
// timing. Helper for TokenValidator implementations.
func ConstantTimeTokenEq(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
