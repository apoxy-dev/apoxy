//go:build linux

package sandbox

import (
	"fmt"
	"net/netip"
	"sync/atomic"
)

// ipAllocator assigns /30 subnets sequentially from 10.200.0.0/16.
// Subnet 1 = 10.200.0.4/30 → gw .5, ctr .6
// Subnet 2 = 10.200.0.8/30 → gw .9, ctr .10
// ...etc. Wraps into the third octet as needed.
//
// The IPs are written into the sentrystack init payload and used to
// populate the in-Sentry PluginStack's eth0 + cosmetic default gateway;
// they don't back a real kernel TAP. The sandbox's /etc/resolv.conf still
// names the gateway IP so glibc/musl have a syntactically valid resolver
// — an installed in-Sentry UDP/DNS forwarder catches every :53 dial
// regardless of dst.
var ipCounter atomic.Uint64

// maxSubnets is the number of /30 subnets available in 10.200.0.0/16.
const maxSubnets = 16384

func allocateIPs() (gw netip.Addr, container netip.Addr, err error) {
	n := uint32(ipCounter.Add(1))
	if n > maxSubnets {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("IP pool exhausted: %d exceeds %d available /30 subnets", n, maxSubnets)
	}
	offset := n * 4 // each /30 consumes 4 addresses
	prefix := netip.AddrFrom4([4]byte{10, 200, 0, 0})
	base := prefix.As4()
	// Add offset to the 16-bit host part (octets 2-3 of the host portion).
	hostBits := uint32(base[2])<<8 | uint32(base[3])
	hostBits += offset
	base[2] = byte(hostBits >> 8)
	base[3] = byte(hostBits)
	gw = netip.AddrFrom4([4]byte{base[0], base[1], base[2], base[3] + 1})
	container = netip.AddrFrom4([4]byte{base[0], base[1], base[2], base[3] + 2})
	return gw, container, nil
}
