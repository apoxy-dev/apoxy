package bifurcate_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
)

// TestBifurcate_AddrSurvivesBurst is a regression test for a data race in which
// the bifurcator reused the gBatch/oBatch backing arrays while handing them to
// the receiver over a channel by reference. A producer running ahead of a slow
// receiver overwrote message slots that had not yet been read, delivering a
// different message's buffer and a nil/wrong source address. Under load this
// nulled the source address on the large majority of frames.
//
// Run with -race to also catch the underlying read/write race directly.
func TestBifurcate_AddrSurvivesBurst(t *testing.T) {
	rxConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	pcRx, err := batchpc.New("udp4", rxConn)
	require.NoError(t, err)
	geneveRx, _ := bifurcate.Bifurcate(pcRx) // discard the non-geneve half

	txConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer txConn.Close()
	wantPort := txConn.LocalAddr().(*net.UDPAddr).Port
	dst := rxConn.LocalAddr().(*net.UDPAddr)

	const total = 2000
	go func() {
		frame := make([]byte, 64) // version 0, proto 0 -> classified as geneve
		for i := 0; i < total; i++ {
			_, _ = txConn.WriteTo(frame, dst)
		}
		time.Sleep(300 * time.Millisecond) // let the reader drain
		_ = rxConn.Close()                 // unblock the reader with ErrClosed
	}()

	buf := make([]byte, 2048)
	got, nilAddr, wrongAddr := 0, 0, 0
	for {
		_, addr, err := geneveRx.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}
		got++
		ua, ok := addr.(*net.UDPAddr)
		switch {
		case !ok || ua == nil:
			nilAddr++
		case ua.Port != wantPort:
			wrongAddr++
		}
	}
	require.Positive(t, got, "no frames delivered")
	require.Zero(t, nilAddr, "delivered frames with a nil source address (slice-aliasing race)")
	require.Zero(t, wrongAddr, "delivered frames with the wrong source address (slice-aliasing race)")
}
