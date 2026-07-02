// Package ipam implements DHCP-style virtual IP assignment for a network's
// CIDR: each joining node is leased the lowest free address, and addresses
// are returned to the pool when a node is removed.
package ipam

import (
	"errors"
	"fmt"
	"net/netip"
)

var ErrPoolExhausted = errors.New("ipam: address pool exhausted")

// Pool allocates addresses from a prefix. It is not safe for concurrent use;
// callers must synchronize (the control server holds its state lock).
type Pool struct {
	prefix netip.Prefix
	used   map[netip.Addr]bool
}

// New creates a pool over the given IPv4 prefix. The network and broadcast
// addresses, and the first host address (reserved for future gateway use),
// are never allocated.
func New(prefix netip.Prefix) (*Pool, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("ipam: only IPv4 prefixes are supported, got %v", prefix)
	}
	if prefix.Bits() > 30 {
		return nil, fmt.Errorf("ipam: prefix %v too small", prefix)
	}
	return &Pool{prefix: prefix.Masked(), used: make(map[netip.Addr]bool)}, nil
}

// Prefix returns the pool's prefix.
func (p *Pool) Prefix() netip.Prefix { return p.prefix }

// MarkUsed records an address as allocated (used when reloading persisted
// state). Addresses outside the prefix are ignored.
func (p *Pool) MarkUsed(addr netip.Addr) {
	if p.prefix.Contains(addr) {
		p.used[addr] = true
	}
}

// Allocate leases the lowest free address in the pool.
func (p *Pool) Allocate() (netip.Addr, error) {
	network := p.prefix.Addr()
	broadcast := lastAddr(p.prefix)
	// Skip the network address and the first host address (.1), which is
	// left free so operators can renumber a router onto it later.
	addr := network.Next().Next()
	for ; addr.IsValid() && addr.Compare(broadcast) < 0; addr = addr.Next() {
		if !p.used[addr] {
			p.used[addr] = true
			return addr, nil
		}
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Release returns an address to the pool.
func (p *Pool) Release(addr netip.Addr) {
	delete(p.used, addr)
}

func lastAddr(p netip.Prefix) netip.Addr {
	a4 := p.Addr().As4()
	bits := p.Bits()
	for i := bits; i < 32; i++ {
		a4[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(a4)
}
