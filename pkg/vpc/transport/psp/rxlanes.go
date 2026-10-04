// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net"
	"net/netip"
	"path/filepath"

	"github.com/apoxy-dev/softpsp/keys"
)

// sysNet is the sysfs directory of the network devices.
const sysNet = "/sys/class/net"

// RxLanes returns the receive lanes for a peer at addr on a direct path with
// no NAT: the RX queue count of the link to addr, at most keys.MaxLanes. It
// returns 1 when it cannot find the link.
func RxLanes(addr netip.Addr) int {
	dev := linkTo(addr)
	if dev == "" {
		return 1
	}
	return rxQueues(sysNet, dev)
}

// linkTo returns the name of the device with the source address for addr, or
// "" when it cannot find it.
func linkTo(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	// Connect on a UDP socket selects the source address and sends nothing.
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 9)))
	if err != nil {
		return ""
	}
	local := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap().WithZone("")
	_ = c.Close()
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == local {
					return ifi.Name
				}
			}
		}
	}
	return ""
}

// rxQueues returns the RX queue count of dev in the sysfs directory root,
// from 1 to keys.MaxLanes.
func rxQueues(root, dev string) int {
	q, _ := filepath.Glob(filepath.Join(root, dev, "queues", "rx-*"))
	return min(max(len(q), 1), keys.MaxLanes)
}
