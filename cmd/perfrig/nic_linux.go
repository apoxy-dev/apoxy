package main

import (
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Netdev generic netlink API (kernel 6.3 and later).
const (
	netdevCmdDevGet       = 1
	netdevAttrIfindex     = 1
	netdevAttrXDPFeatures = 3
	netdevAttrXDPZCSegs   = 4
)

// genlHeader is a generic netlink header. nl.Genlmsg writes 2 random bytes into
// the reserved field, and the kernel then rejects the request.
type genlHeader struct{ cmd, version uint8 }

func (h genlHeader) Len() int          { return nl.SizeofGenlmsg }
func (h genlHeader) Serialize() []byte { return []byte{h.cmd, h.version, 0, 0} }

// xdpFeatures asks the netdev API for the XDP features of dev. It returns
// nothing when the kernel does not report them or the driver has none.
func xdpFeatures(dev string) ([]string, uint32) {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, 0
	}
	fam, err := netlink.GenlFamilyGet("netdev")
	if err != nil {
		slog.Debug("The kernel has no netdev generic netlink family", "error", err)
		return nil, 0
	}
	req := nl.NewNetlinkRequest(int(fam.ID), unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	req.AddData(genlHeader{cmd: netdevCmdDevGet, version: 1})
	req.AddData(nl.NewRtAttr(netdevAttrIfindex, nl.Uint32Attr(uint32(ifi.Index))))
	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		slog.Warn("Failed to read the XDP features", "dev", dev, "error", err)
		return nil, 0
	}
	native := nl.NativeEndian()
	var mask uint64
	var segs uint32
	for _, m := range msgs {
		attrs, err := nl.ParseRouteAttr(m[nl.SizeofGenlmsg:])
		if err != nil {
			continue
		}
		for _, a := range attrs {
			switch a.Attr.Type {
			case netdevAttrXDPFeatures:
				if len(a.Value) >= 8 {
					mask = native.Uint64(a.Value)
				}
			case netdevAttrXDPZCSegs:
				if len(a.Value) >= 4 {
					segs = native.Uint32(a.Value)
				}
			}
		}
	}
	return xdpFeatureList(mask), segs
}
