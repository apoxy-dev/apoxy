package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/safchain/ethtool"
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

// linkSettleTimeout is the longest wait for the address of a link after a change.
const linkSettleTimeout = time.Minute

// readLink returns the settings of dev that prepareXDP changes, and the most
// combined channels of dev.
func readLink(dev string) (linkConf, uint32, error) {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return linkConf{}, 0, err
	}
	defer e.Close()
	ch, err := e.GetChannels(dev)
	if err != nil {
		return linkConf{}, 0, fmt.Errorf("read the channels of %s: %w", dev, err)
	}
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return linkConf{}, 0, err
	}
	fwd, err := os.ReadFile(forwardingPath(dev))
	if err != nil {
		return linkConf{}, 0, err
	}
	return linkConf{channels: ch.CombinedCount, mtu: ifi.MTU, forwarding: strings.TrimSpace(string(fwd))}, ch.MaxCombined, nil
}

// forwardingPath is the file of the IPv4 forwarding of dev.
func forwardingPath(dev string) string {
	return "/proc/sys/net/ipv4/conf/" + dev + "/forwarding"
}

// setLink gives dev the settings c. The driver stops the link when the channels
// change, so setLink then waits until ip stays on dev for the time settle.
func setLink(ctx context.Context, dev, ip string, c linkConf, settle time.Duration) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer e.Close()
	ch, err := e.GetChannels(dev)
	if err != nil {
		return fmt.Errorf("read the channels of %s: %w", dev, err)
	}
	if ch.CombinedCount != c.channels {
		ch.CombinedCount = c.channels
		if _, err := e.SetChannels(dev, ch); err != nil {
			return fmt.Errorf("set %d channels on %s: %w", c.channels, dev, err)
		}
	}
	// A DHCP client can set the MTU of its lease again when the link comes back.
	if err := waitAddr(ctx, dev, ip, settle, linkSettleTimeout); err != nil {
		return err
	}
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}
	if l.Attrs().MTU != c.mtu {
		if err := netlink.LinkSetMTU(l, c.mtu); err != nil {
			return fmt.Errorf("set the MTU %d on %s: %w", c.mtu, dev, err)
		}
	}
	return os.WriteFile(forwardingPath(dev), []byte(c.forwarding), 0o644)
}

// waitAddr waits until dev is up and has the address ip for the time hold. After
// the link stops, the host can take the address off and get it again with DHCP.
func waitAddr(ctx context.Context, dev, ip string, hold, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var since time.Time
	for {
		now := time.Now()
		ifi, err := net.InterfaceByName(dev)
		got, aerr := devIPv4(dev)
		switch {
		case err != nil || aerr != nil || got != ip || ifi.Flags&net.FlagRunning == 0:
			since = time.Time{}
		case since.IsZero():
			since = now
		case now.Sub(since) >= hold:
			return nil
		}
		if now.After(deadline) {
			return fmt.Errorf("%s did not keep the address %s for %s in %s", dev, ip, hold, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(hold, 100*time.Millisecond)):
		}
	}
}

// prepareXDP gives dev the settings that an XDP program needs: in driver mode with
// at most channels channels if channels is above 0, or in generic mode. The
// returned function sets the old settings again.
func prepareXDP(ctx context.Context, dev, ip string, channels uint32, generic bool, settle time.Duration) (func(), error) {
	old, maxChannels, err := readLink(dev)
	if err != nil {
		return nil, err
	}
	want := xdpConf(old, maxChannels, channels, generic)
	undo := func() {
		// The context of the row can be done here.
		ctx, cancel := context.WithTimeout(context.Background(), 2*linkSettleTimeout)
		defer cancel()
		if err := setLink(ctx, dev, ip, old, settle); err != nil {
			slog.Warn("Failed to set the old link settings again", "dev", dev, "error", err)
		}
	}
	if err := setLink(ctx, dev, ip, want, settle); err != nil {
		undo()
		return nil, err
	}
	slog.Info("Made the link ready for XDP", "dev", dev, "generic", generic, "channels", want.channels, "old_channels", old.channels,
		"max_channels", maxChannels, "mtu", want.mtu, "old_mtu", old.mtu)
	return undo, nil
}
