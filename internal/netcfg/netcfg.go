// Package netcfg applies OS network configuration for the virtual
// interface: address assignment, routes, internet-passthrough (exit node)
// client routes, and gateway NAT. Linux, macOS and Windows are supported via
// the platform's standard tooling (ip/route/ifconfig/netsh/powershell).
package netcfg

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

// Manager tracks the routes it installed so they can be cleaned up.
type Manager struct {
	log    *slog.Logger
	ifName string

	mu      sync.Mutex
	exitOn  bool
	origGW  netip.Addr // physical default gateway captured when exit mode enabled
	origIf  string
	pinned  map[netip.Addr]bool // host routes forced via the physical gateway
	natCIDR netip.Prefix        // non-zero when gateway NAT is active
}

// NewManager creates a Manager for the given interface.
func NewManager(ifName string, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{log: log, ifName: ifName, pinned: map[netip.Addr]bool{}}
}

// ConfigureInterface assigns addr (with its prefix length) to the interface,
// sets the MTU, brings it up, and ensures the network route points at it.
func (m *Manager) ConfigureInterface(addr netip.Prefix, mtu int) error {
	return configureInterface(m.ifName, addr, mtu)
}

// EnableExit routes all internet traffic through the virtual interface,
// pinning the control/relay server addresses (and any already-pinned peer
// endpoints) to the physical default gateway so the tunnel's own packets
// don't loop back into the tunnel.
func (m *Manager) EnableExit(pin []netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exitOn {
		return nil
	}
	gw, ifName, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("discovering physical default gateway: %w", err)
	}
	m.origGW, m.origIf = gw, ifName
	for _, a := range pin {
		if err := m.pinLocked(a); err != nil {
			m.log.Warn("pinning host route failed", "addr", a, "err", err)
		}
	}
	// Two /1 routes take priority over the physical /0 default without
	// removing it.
	for _, p := range exitPrefixes() {
		if err := addRoute(p, m.ifName); err != nil {
			m.rollbackExitLocked()
			return fmt.Errorf("adding exit route %v: %w", p, err)
		}
	}
	m.exitOn = true
	m.log.Info("internet passthrough enabled", "via", m.ifName)
	return nil
}

// DisableExit removes the exit routes and pinned host routes.
func (m *Manager) DisableExit() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.exitOn {
		return nil
	}
	m.rollbackExitLocked()
	m.exitOn = false
	m.log.Info("internet passthrough disabled")
	return nil
}

func (m *Manager) rollbackExitLocked() {
	for _, p := range exitPrefixes() {
		if err := delRoute(p, m.ifName); err != nil {
			m.log.Debug("removing exit route", "prefix", p, "err", err)
		}
	}
	for a := range m.pinned {
		if err := delHostRoute(a, m.origGW, m.origIf); err != nil {
			m.log.Debug("removing pinned route", "addr", a, "err", err)
		}
		delete(m.pinned, a)
	}
}

// Pin ensures addr is routed via the physical gateway. Called for newly
// discovered peer endpoints while exit mode is active. No-op when exit mode
// is off (the physical default route already applies).
func (m *Manager) Pin(addr netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.exitOn || m.pinned[addr] {
		return
	}
	if err := m.pinLocked(addr); err != nil {
		m.log.Warn("pinning host route failed", "addr", addr, "err", err)
	}
}

func (m *Manager) pinLocked(addr netip.Addr) error {
	if !addr.Is4() || addr.IsLoopback() {
		return nil
	}
	if err := addHostRoute(addr, m.origGW, m.origIf); err != nil {
		return err
	}
	m.pinned[addr] = true
	return nil
}

// ExitActive reports whether exit routes are installed.
func (m *Manager) ExitActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exitOn
}

// EnableGatewayNAT turns this host into the internet gateway for the virtual
// network: IP forwarding on, NAT from the overlay CIDR out the physical
// interface.
func (m *Manager) EnableGatewayNAT(cidr netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.natCIDR.IsValid() {
		return nil
	}
	if err := enableNAT(cidr); err != nil {
		return err
	}
	m.natCIDR = cidr
	m.log.Info("gateway NAT enabled", "cidr", cidr)
	return nil
}

// DisableGatewayNAT removes the NAT rules installed by EnableGatewayNAT.
func (m *Manager) DisableGatewayNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.natCIDR.IsValid() {
		return nil
	}
	err := disableNAT(m.natCIDR)
	m.natCIDR = netip.Prefix{}
	if err != nil {
		return err
	}
	m.log.Info("gateway NAT disabled")
	return nil
}

// Cleanup restores all routing changes.
func (m *Manager) Cleanup() {
	m.DisableExit()
	m.DisableGatewayNAT()
}

func exitPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
}

// run executes a command and returns a descriptive error on failure.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runOut executes a command and returns its stdout.
func runOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func maskFromBits(bits int) string {
	var m [4]byte
	for i := 0; i < bits; i++ {
		m[i/8] |= 1 << (7 - i%8)
	}
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}
