package bifurcate

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

func TestReadFromSkipsEmptyPendingBatch(t *testing.T) {
	pc := &chanPacketConn{
		ch:     make(chan []*batchpc.Message, 2),
		closed: make(chan struct{}),
	}
	want := []byte("next packet")
	buf := make([]byte, len(want), 65535)
	copy(buf, want)
	wantAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6081}
	pc.ch <- nil
	pc.ch <- []*batchpc.Message{{Buf: buf, Addr: wantAddr}}

	got := make([]byte, 64)
	n, addr, err := pc.ReadFrom(got)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, got[:n]))
	require.Equal(t, wantAddr, addr)
}
