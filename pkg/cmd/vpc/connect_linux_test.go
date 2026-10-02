package vpc

import (
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"

	"github.com/apoxy-dev/apoxy/pkg/netns"
)

// TestTunRoutes checks the kernel routes of the tun driver in a new network
// namespace.
func TestTunRoutes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a network namespace")
	}
	ns := newNetns(t)
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	steps := []struct {
		name        string
		add, remove []netip.Prefix
		want        []netip.Prefix // Routes on the device after the step.
	}{
		{
			name: "add",
			add: pfx("10.9.0.0/16", "fd99::/64", "0.0.0.0/0", "::/0",
				"fd61:706f:7879:12:3456:7800::/96", "fd61:706f:7879::/48", "10.7.0.0/16"),
			want: pfx("10.9.0.0/16", "fd99::/64"),
		},
		{name: "add again", add: pfx("10.9.0.0/16"), want: pfx("10.9.0.0/16", "fd99::/64")},
		{name: "remove", remove: pfx("10.9.0.0/16", "10.7.0.0/16"), want: pfx("fd99::/64")},
		{name: "remove all", remove: pfx("fd99::/64"), want: nil},
	}
	all := pfx("10.9.0.0/16", "fd99::/64", "0.0.0.0/0", "::/0", "fd61:706f:7879:12:3456:7800::/96", "fd61:706f:7879::/48", "10.7.0.0/16")
	err := netns.Do(ns, func() error {
		vpc0, lan0 := upVeth(t, "vpc0"), upVeth(t, "lan0")
		// A host route that a VPC route must not replace.
		lan := netip.MustParsePrefix("10.7.0.0/16")
		require.NoError(t, netlink.RouteAdd(&netlink.Route{LinkIndex: lan0.Attrs().Index, Dst: ipNet(lan)}))

		dev := &tunDev{link: vpc0, vpc: netip.MustParsePrefix("fd61:706f:7879:12:3400::/72"), routes: map[netip.Prefix]bool{}}
		for _, st := range steps {
			dev.route(st.add, st.remove)
			onDev := routesOn(t, vpc0)
			for _, p := range all {
				require.Equal(t, slices.Contains(st.want, p), onDev[p], "%s: route %s", st.name, p)
			}
			require.True(t, routesOn(t, lan0)[lan], "%s: the host route %s went away", st.name, lan)
		}
		return nil
	})
	require.NoError(t, err)
}

// routesOn returns the destinations of the routes on link.
func routesOn(t *testing.T, link netlink.Link) map[netip.Prefix]bool {
	t.Helper()
	rs, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	require.NoError(t, err)
	out := map[netip.Prefix]bool{}
	for _, r := range rs {
		if r.Dst == nil {
			continue
		}
		a, _ := netip.AddrFromSlice(r.Dst.IP)
		bits, _ := r.Dst.Mask.Size()
		out[netip.PrefixFrom(a.Unmap(), bits)] = true
	}
	return out
}

// upVeth makes a veth pair name and name-peer, and sets both ends up.
func upVeth(t *testing.T, name string) netlink.Link {
	t.Helper()
	require.NoError(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "-peer"}))
	for _, n := range []string{name + "-peer", name} {
		l, err := netlink.LinkByName(n)
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(l))
	}
	l, err := netlink.LinkByName(name)
	require.NoError(t, err)
	return l
}

func newNetns(t *testing.T) vnetns.NsHandle {
	t.Helper()
	type result struct {
		ns  vnetns.NsHandle
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// The thread stays locked, so it ends with the goroutine.
		runtime.LockOSThread()
		ns, err := vnetns.New()
		ch <- result{ns, err}
	}()
	res := <-ch
	if res.err != nil {
		t.Skipf("cannot make a network namespace: %v", res.err)
	}
	t.Cleanup(func() { _ = res.ns.Close() })
	return res.ns
}
