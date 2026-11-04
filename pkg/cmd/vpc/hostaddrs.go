package vpc

import (
	"net"
	"net/netip"
)

// hostAddrs lists the addresses of the host interfaces for the host candidates
// of the agent. family is the network of the agent socket: udp, udp4 or udp6.
type hostAddrs struct{ family string }

// HostAddrs returns the unicast addresses of the interfaces that are up and not
// loopback, in the address family of the agent socket.
func (h hostAddrs) HostAddrs() ([]netip.Addr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			// An interface that goes away during the list has no addresses.
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			switch {
			case !ip.IsGlobalUnicast():
			case h.family == "udp4" && !ip.Is4(), h.family == "udp6" && ip.Is4():
			default:
				out = append(out, ip)
			}
		}
	}
	return out, nil
}
