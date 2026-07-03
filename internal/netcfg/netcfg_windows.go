package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

func powershell(script string) (string, error) {
	return runOut("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

func configureInterface(ifName string, addr netip.Prefix, mtu int) error {
	if err := run("netsh", "interface", "ipv4", "set", "address",
		"name="+ifName, "source=static",
		"address="+addr.Addr().String(), "mask="+maskFromBits(addr.Bits())); err != nil {
		return err
	}
	return run("netsh", "interface", "ipv4", "set", "subinterface",
		ifName, fmt.Sprintf("mtu=%d", mtu), "store=active")
}

func addRoute(dst netip.Prefix, ifName string) error {
	// On-link route through the TUN adapter.
	run("netsh", "interface", "ipv4", "delete", "route", dst.String(), ifName)
	return run("netsh", "interface", "ipv4", "add", "route", dst.String(), ifName, "metric=5")
}

func delRoute(dst netip.Prefix, ifName string) error {
	return run("netsh", "interface", "ipv4", "delete", "route", dst.String(), ifName)
}

func defaultGateway() (netip.Addr, string, error) {
	out, err := powershell(`$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -AddressFamily IPv4 | Sort-Object RouteMetric,ifMetric | Select-Object -First 1; "$($r.NextHop)|$($r.InterfaceAlias)"`)
	if err != nil {
		return netip.Addr{}, "", err
	}
	parts := strings.SplitN(strings.TrimSpace(out), "|", 2)
	if len(parts) != 2 {
		return netip.Addr{}, "", errors.New("no default route found")
	}
	gw, err := netip.ParseAddr(parts[0])
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("no default route found: %w", err)
	}
	return gw, parts[1], nil
}

func addHostRoute(dst, gw netip.Addr, ifName string) error {
	run("route", "delete", dst.String())
	return run("route", "add", dst.String(), "mask", "255.255.255.255", gw.String())
}

func delHostRoute(dst, gw netip.Addr, ifName string) error {
	return run("route", "delete", dst.String())
}

func enableNAT(cidr netip.Prefix) error {
	// Windows NAT via the built-in NetNat (requires Pro/Server with the
	// WinNAT service). Forwarding must be on for the TUN interface too.
	if _, err := powershell(`Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled`); err != nil {
		return err
	}
	// A NAT from a previous run may still exist (locale-proof check, since
	// error strings are localized).
	if _, err := powershell(`Get-NetNat -Name vvvlan -ErrorAction Stop`); err == nil {
		return nil
	}
	// The WinNAT service is frequently stopped even where it is installed.
	powershell(`Start-Service winnat`) // best effort
	_, err := powershell(fmt.Sprintf(`New-NetNat -Name vvvlan -InternalIPInterfaceAddressPrefix %s`, cidr))
	if err != nil {
		// HRESULT 0x80041010 (WBEM_E_INVALID_CLASS): the NetNat WMI class
		// does not exist — this Windows edition has no WinNAT (e.g. Home).
		if strings.Contains(err.Error(), "0x80041010") {
			return fmt.Errorf("this Windows edition does not support NetNat (WinNAT is unavailable, typically on Windows Home) — designate a Linux/macOS node, or a Windows Pro/Server machine, as the network gateway instead: %w", err)
		}
		return err
	}
	return nil
}

func disableNAT(cidr netip.Prefix) error {
	_, err := powershell(`Remove-NetNat -Name vvvlan -Confirm:$false`)
	return err
}
