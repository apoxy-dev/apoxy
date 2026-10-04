// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestSockBufs checks that New sets 16 MiB buffers on the agent socket, that
// ReadLanes sets them on the lane sockets, and that a lane socket that only
// sends gets a small receive buffer. With no CAP_NET_ADMIN the kernel limits
// them to rmem_max and wmem_max. The kernel reports twice the size.
func TestSockBufs(t *testing.T) {
	dm := &Demux{}
	tr := demuxTransport(t, dm)
	b, err := New(Config{Transport: tr, Demux: dm})
	require.NoError(t, err)
	defer b.Close()
	require.Len(t, b.OpenLanes(2), 1)
	require.NoError(t, b.ReadLanes())
	require.Len(t, b.OpenLanes(3), 2)
	admin := netAdmin(t)
	cases := []struct {
		name     string
		c        *net.UDPConn
		rcv, snd int
	}{
		{"agent socket", tr.Conn.(*net.UDPConn), sockBuf, sockBuf},
		{"lane socket that reads", b.laneConns[1].Load(), sockBuf, sockBuf},
		{"lane socket that only sends", b.laneConns[2].Load(), laneRcvBuf, sockBuf},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := tc.c.SyscallConn()
			require.NoError(t, err)
			for _, o := range []struct {
				opt   int
				limit string
				want  int
			}{{unix.SO_RCVBUF, "rmem_max", tc.rcv}, {unix.SO_SNDBUF, "wmem_max", tc.snd}} {
				want := o.want
				if !admin {
					want = min(want, sysctl(t, "/proc/sys/net/core/"+o.limit))
				}
				var got int
				var gerr error
				require.NoError(t, rc.Control(func(fd uintptr) { got, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, o.opt) }))
				require.NoError(t, gerr)
				assert.Equal(t, 2*want, got, "%s, CAP_NET_ADMIN %t", o.limit, admin)
			}
		})
	}
}

// netAdmin reports whether the process has CAP_NET_ADMIN.
func netAdmin(t *testing.T) bool {
	status, err := os.ReadFile("/proc/self/status")
	require.NoError(t, err)
	for line := range strings.Lines(string(status)) {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			require.NoError(t, err)
			return caps&(1<<unix.CAP_NET_ADMIN) != 0
		}
	}
	return false
}

func sysctl(t *testing.T, path string) int {
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	require.NoError(t, err)
	return n
}
