package batchpc_test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

// TestWriteBatch_SendsEntireBatch is a regression test for WriteBatch silently
// dropping the unsent tail of a batch. sendmmsg returns the number of messages
// actually sent, which can be fewer than offered (EAGAIN, a mid-batch error, or
// a platform with no batch syscall where x/net sends a single message per call
// and reports n=1 — darwin et al.). The old code ignored that count and dropped
// the rest; WriteBatch must loop until the whole batch is on the wire.
func TestWriteBatch_SendsEntireBatch(t *testing.T) {
	rxConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer rxConn.Close()

	txConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	tx, err := batchpc.New("udp4", txConn)
	require.NoError(t, err)
	defer tx.Close()

	dst := rxConn.LocalAddr().(*net.UDPAddr)

	const batch = 20
	msgs := make([]batchpc.Message, batch)
	for i := range msgs {
		msgs[i] = batchpc.Message{Buf: []byte{byte(i)}, Addr: dst}
	}

	n, err := tx.WriteBatch(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, batch, n, "WriteBatch must report the whole batch sent")

	// Confirm every datagram actually reached the wire.
	seen := make(map[byte]bool)
	buf := make([]byte, 64)
	_ = rxConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for len(seen) < batch {
		nn, _, rerr := rxConn.ReadFrom(buf)
		if rerr != nil {
			break
		}
		if nn == 1 {
			seen[buf[0]] = true
		}
	}
	require.Len(t, seen, batch, "WriteBatch dropped part of the batch: only %d/%d datagrams arrived", len(seen), batch)
}
