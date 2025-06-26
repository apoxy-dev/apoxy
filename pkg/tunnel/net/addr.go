package net

import (
	"fmt"
	"net"
)

// Get local IPv6 address by scanning for global unicast addrs in netlink.
func GetLocalIPv6Address(ifcName string) (*net.IPAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

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

			// Check if it's IPv6 and global unicast
			if ipNet.IP.To4() == nil && ipNet.IP.IsGlobalUnicast() {
				return &net.IPAddr{IP: ipNet.IP}, nil
			}
		}
	}

	return nil, fmt.Errorf("no global unicast IPv6 address found")
}
