package bifurcate

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

func TestReadFromSkipsEmptyPendingBatch(t *testing.T) {
	pc := newChanPacketConn(nil, new(atomic.Int32))
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

func BenchmarkReadFrom(b *testing.B) {
	cases := []struct {
		name     string
		deadline time.Time
	}{
		{name: "no deadline"},
		{name: "deadline", deadline: time.Now().Add(time.Hour)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			pc := newChanPacketConn(nil, new(atomic.Int32))
			if !tc.deadline.IsZero() {
				_ = pc.SetReadDeadline(tc.deadline)
			}
			batch := make([]*batchpc.Message, 1)
			buf := make([]byte, 1500)
			b.ReportAllocs()
			for b.Loop() {
				batch[0] = messagePool.Get().(*batchpc.Message)
				pc.ch <- batch
				if _, _, err := pc.ReadFrom(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
