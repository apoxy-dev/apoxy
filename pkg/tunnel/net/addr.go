package net

import (
	"fmt"
	"net"
	"net/netip"
)

// GetGlobalUnicastAddresses returns the global unicast IPv4/IPv6 address of the specified interface.
func GetGlobalUnicastAddresses(ifcName string) ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var out []netip.Prefix
	for _, iface := range interfaces {
		if ifcName != "" && iface.Name != ifcName {
			continue
		}

		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if !ipNet.IP.IsGlobalUnicast() {
				continue
			}

			var ip netip.Addr
			if ipNet.IP.To4() != nil {
				ip, ok = netip.AddrFromSlice(ipNet.IP.To4())
			} else {
				ip, ok = netip.AddrFromSlice(ipNet.IP.To16())
			}
			if !ok {
				continue
			}

			ones, _ := ipNet.Mask.Size()
			out = append(out, netip.PrefixFrom(ip, ones))
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no global unicast addresses found on the interface %s", ifcName)
	}

	return out, nil
}
