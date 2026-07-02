package netcfg

import (
	"fmt"
	"net/netip"
	"strings"
)

func configureInterface(ifName string, addr netip.Prefix, mtu int) error {
	if err := run("ip", "addr", "replace", addr.String(), "dev", ifName); err != nil {
		return err
	}
	return run("ip", "link", "set", "dev", ifName, "up", "mtu", fmt.Sprint(mtu))
}

func addRoute(dst netip.Prefix, ifName string) error {
	return run("ip", "route", "replace", dst.String(), "dev", ifName)
}

func delRoute(dst netip.Prefix, ifName string) error {
	return run("ip", "route", "del", dst.String(), "dev", ifName)
}

func defaultGateway() (netip.Addr, string, error) {
	out, err := runOut("ip", "-4", "route", "show", "default")
	if err != nil {
		return netip.Addr{}, "", err
	}
	// e.g. "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
	fields := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	var gw netip.Addr
	var ifName string
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "via":
			gw, _ = netip.ParseAddr(fields[i+1])
		case "dev":
			ifName = fields[i+1]
		}
	}
	if !gw.IsValid() || ifName == "" {
		return netip.Addr{}, "", fmt.Errorf("no default route found in %q", strings.TrimSpace(out))
	}
	return gw, ifName, nil
}

func addHostRoute(dst, gw netip.Addr, ifName string) error {
	return run("ip", "route", "replace", dst.String()+"/32", "via", gw.String(), "dev", ifName)
}

func delHostRoute(dst, gw netip.Addr, ifName string) error {
	return run("ip", "route", "del", dst.String()+"/32")
}

func enableNAT(cidr netip.Prefix) error {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	_, extIf, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("finding internet-facing interface: %w", err)
	}
	rules := [][]string{
		{"-t", "nat", "-A", "POSTROUTING", "-s", cidr.String(), "-o", extIf, "-j", "MASQUERADE"},
		{"-A", "FORWARD", "-s", cidr.String(), "-j", "ACCEPT"},
		{"-A", "FORWARD", "-d", cidr.String(), "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	for _, r := range rules {
		if err := run("iptables", r...); err != nil {
			return err
		}
	}
	return nil
}

func disableNAT(cidr netip.Prefix) error {
	_, extIf, err := defaultGateway()
	if err != nil {
		return err
	}
	rules := [][]string{
		{"-t", "nat", "-D", "POSTROUTING", "-s", cidr.String(), "-o", extIf, "-j", "MASQUERADE"},
		{"-D", "FORWARD", "-s", cidr.String(), "-j", "ACCEPT"},
		{"-D", "FORWARD", "-d", cidr.String(), "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	var firstErr error
	for _, r := range rules {
		if err := run("iptables", r...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
