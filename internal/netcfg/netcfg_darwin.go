package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

func configureInterface(ifName string, addr netip.Prefix, mtu int) error {
	ip := addr.Addr().String()
	// utun interfaces are point-to-point: assign our address as both ends,
	// then route the whole overlay prefix at the interface.
	if err := run("ifconfig", ifName, "inet", ip, ip, "netmask", maskFromBits(addr.Bits()), "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return err
	}
	return addRoute(addr.Masked(), ifName)
}

func addRoute(dst netip.Prefix, ifName string) error {
	// -n avoids reverse-DNS stalls; replace semantics via delete-then-add.
	run("route", "-n", "delete", "-net", dst.String())
	return run("route", "-n", "add", "-net", dst.String(), "-interface", ifName)
}

func delRoute(dst netip.Prefix, ifName string) error {
	return run("route", "-n", "delete", "-net", dst.String())
}

func defaultGateway() (netip.Addr, string, error) {
	out, err := runOut("route", "-n", "get", "default")
	if err != nil {
		return netip.Addr{}, "", err
	}
	var gw netip.Addr
	var ifName string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "gateway: "); ok {
			gw, _ = netip.ParseAddr(v)
		}
		if v, ok := strings.CutPrefix(line, "interface: "); ok {
			ifName = v
		}
	}
	if !gw.IsValid() || ifName == "" {
		return netip.Addr{}, "", errors.New("no default route found")
	}
	return gw, ifName, nil
}

func addHostRoute(dst, gw netip.Addr, ifName string) error {
	run("route", "-n", "delete", "-host", dst.String())
	return run("route", "-n", "add", "-host", dst.String(), gw.String())
}

func delHostRoute(dst, gw netip.Addr, ifName string) error {
	return run("route", "-n", "delete", "-host", dst.String())
}

func enableNAT(cidr netip.Prefix) error {
	if err := run("sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		return err
	}
	// Loading pf NAT rules programmatically risks clobbering user pf config,
	// so we require a one-time manual step on macOS gateways.
	return fmt.Errorf(`automatic NAT setup is not supported on macOS; IP forwarding was enabled, now add a pf NAT rule manually:

  echo 'nat on en0 from %s to any -> (en0)' | sudo pfctl -f - -e

(replace en0 with your internet-facing interface)`, cidr)
}

func disableNAT(cidr netip.Prefix) error {
	return run("sysctl", "-w", "net.inet.ip.forwarding=0")
}
