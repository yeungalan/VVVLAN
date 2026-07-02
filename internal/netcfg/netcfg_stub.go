//go:build !linux && !darwin && !windows

package netcfg

import (
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("netcfg: unsupported platform")

func configureInterface(ifName string, addr netip.Prefix, mtu int) error { return errUnsupported }
func addRoute(dst netip.Prefix, ifName string) error                     { return errUnsupported }
func delRoute(dst netip.Prefix, ifName string) error                     { return errUnsupported }
func defaultGateway() (netip.Addr, string, error) {
	return netip.Addr{}, "", errUnsupported
}
func addHostRoute(dst, gw netip.Addr, ifName string) error { return errUnsupported }
func delHostRoute(dst, gw netip.Addr, ifName string) error { return errUnsupported }
func enableNAT(cidr netip.Prefix) error                    { return errUnsupported }
func disableNAT(cidr netip.Prefix) error                   { return errUnsupported }
