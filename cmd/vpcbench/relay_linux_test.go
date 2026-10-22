// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/safchain/ethtool"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The links of TestRelay: the relay device link vb-r and the control link vb-rc in the relay
// netns, joined to vb-p and vb-pc in the netns of the test.
var (
	relayDevIP, peerDevIP = netip.MustParsePrefix("10.99.1.1/24"), netip.MustParsePrefix("10.99.1.2/24")
	relayCtlIP, peerCtlIP = netip.MustParsePrefix("10.99.2.1/24"), netip.MustParsePrefix("10.99.2.2/24")
)

// relayNetns makes the relay netns and its two links. The device link has 4 queues, so that the
// lanes of an agent go to more than one RX queue.
func relayNetns(t *testing.T) netns.NsHandle {
	t.Helper()
	var ns netns.NsHandle
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The thread stays in the new netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		ns, err = netns.New()
	}()
	<-done
	require.NoError(t, err)
	t.Cleanup(func() { ns.Close() })

	h, err := netlink.NewHandleAt(ns)
	require.NoError(t, err)
	defer h.Close()
	addr := func(p netip.Prefix) *netlink.Addr {
		return &netlink.Addr{IPNet: &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}, Flags: unix.IFA_F_NODAD}
	}
	for _, l := range []struct {
		relay, peer     string
		queues          int
		relayIP, peerIP netip.Prefix
	}{
		{relay: "vb-r", peer: "vb-p", queues: 4, relayIP: relayDevIP, peerIP: peerDevIP},
		{relay: "vb-rc", peer: "vb-pc", queues: 1, relayIP: relayCtlIP, peerIP: peerCtlIP},
	} {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: l.peer, NumTxQueues: l.queues, NumRxQueues: l.queues},
			PeerName:  l.relay, PeerNumTxQueues: uint32(l.queues), PeerNumRxQueues: uint32(l.queues),
			PeerNamespace: netlink.NsFd(ns),
		}
		require.NoError(t, netlink.LinkAdd(veth))
		t.Cleanup(func() { _ = netlink.LinkDel(veth) })
		peer, err := netlink.LinkByName(l.peer)
		require.NoError(t, err)
		require.NoError(t, netlink.AddrAdd(peer, addr(l.peerIP)))
		require.NoError(t, netlink.LinkSetUp(peer))
		relay, err := h.LinkByName(l.relay)
		require.NoError(t, err)
		require.NoError(t, h.AddrAdd(relay, addr(l.relayIP)))
		require.NoError(t, h.LinkSetUp(relay))
	}
	// The relay device takes single packets, as from a NIC.
	e, err := ethtool.NewEthtool()
	require.NoError(t, err)
	defer e.Close()
	require.NoError(t, e.Change("vb-p", map[string]bool{"tx-udp-segmentation": false}))
	return ns
}

// enterNetns moves the locked thread into ns, with its own sysfs (the links of ns) and bpffs, as
// "ip netns exec" does for the relay of perfrig.
func enterNetns(ns netns.NsHandle) error {
	if err := netns.Set(ns); err != nil {
		return err
	}
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare the mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make the mounts slave: %w", err)
	}
	if err := unix.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return fmt.Errorf("mount sysfs: %w", err)
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs: %w", err)
	}
	return nil
}

// TestRelay runs the relay on a relay device in its own netns, and the server and the client in
// this process, for one second with each transport.
func TestRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the agents for a few seconds")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for netns, veth and AF_XDP")
	}
	ns := relayNetns(t)
	for _, transport := range []string{"psp", "quic"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			o := options{WorkDir: t.TempDir(), Driver: "netstack", Transport: transport, Via: "relay", StartTimeout: 30 * time.Second}
			ro := o
			ro.Iface, ro.Listen = "vb-r", netip.AddrPortFrom(relayCtlIP.Addr(), 0).String()
			addr := make(chan netip.AddrPort, 1)
			relayErr := make(chan error, 1)
			go func() {
				// The relay opens its device and its control socket in the relay netns. The thread
				// stays there, so it must exit with the goroutine.
				runtime.LockOSThread()
				if err := enterNetns(ns); err != nil {
					relayErr <- err
					return
				}
				relayErr <- runRelay(ctx, ro, func(a netip.AddrPort) { addr <- a })
			}()
			select {
			case a := <-addr:
				o.Relay = a.String()
			case err := <-relayErr:
				t.Fatalf("relay stopped: %v", err)
			}
			runPair(t, o)
			require.NoError(t, <-relayErr, "the client stops the relay")
		})
	}
}
