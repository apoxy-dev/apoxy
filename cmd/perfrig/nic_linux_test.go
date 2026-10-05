package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestGenlHeader(t *testing.T) {
	h := genlHeader{cmd: netdevCmdDevGet, version: 1}
	assert.Equal(t, []byte{1, 1, 0, 0}, h.Serialize())
	assert.Equal(t, len(h.Serialize()), h.Len())
}

func TestWaitAddr(t *testing.T) {
	done, cancel := context.WithCancel(t.Context())
	cancel()
	cases := []struct {
		name    string
		ctx     context.Context
		dev, ip string
		wantErr string
	}{
		{name: "address stays", ctx: t.Context(), dev: "lo", ip: "127.0.0.1"},
		{name: "other address", ctx: t.Context(), dev: "lo", ip: "192.0.2.1", wantErr: "lo did not keep the address 192.0.2.1"},
		{name: "no link", ctx: t.Context(), dev: "perf-none", ip: "127.0.0.1", wantErr: "perf-none did not keep the address"},
		{name: "context is done", ctx: done, dev: "lo", ip: "192.0.2.1", wantErr: "context canceled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			err := waitAddr(tc.ctx, tc.dev, tc.ip, 30*time.Millisecond, 200*time.Millisecond)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, time.Since(start), 30*time.Millisecond)
		})
	}
}

// TestPrepareXDP changes a veth and sets it back. A veth has no combined
// channels, so the test does not change the channels.
func TestPrepareXDP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	const dev, ip = "perf-xdp0", "192.0.2.1"
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: dev, MTU: 9001}, PeerName: "perf-xdp1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("cannot add a veth pair: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	addr, err := netlink.ParseAddr(ip + "/24")
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(veth, addr))
	peer, err := netlink.LinkByName("perf-xdp1")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(veth))
	require.NoError(t, netlink.LinkSetUp(peer))
	require.NoError(t, os.WriteFile(forwardingPath(dev), []byte("0"), 0o644))

	old, _, err := readLink(dev)
	require.NoError(t, err)
	require.Equal(t, linkConf{channels: old.channels, mtu: 9001, forwarding: "0"}, old)

	undo, err := prepareXDP(t.Context(), dev, ip, 20*time.Millisecond)
	require.NoError(t, err)
	got, _, err := readLink(dev)
	require.NoError(t, err)
	assert.Equal(t, linkConf{channels: old.channels, mtu: xdpMaxMTU, forwarding: "1"}, got)

	undo()
	got, _, err = readLink(dev)
	require.NoError(t, err)
	assert.Equal(t, old, got)

	_, err = prepareXDP(t.Context(), "perf-none", ip, 20*time.Millisecond)
	assert.Error(t, err)
}
