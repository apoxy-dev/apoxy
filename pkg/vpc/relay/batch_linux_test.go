// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFwdBatch checks that the batch copies each packet, sends a full batch
// at once, and sends the packets in order. udpbatch tests the GSO messages.
func TestFwdBatch(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{name: "one packet", n: 1},
		{name: "full batch", n: maxFwd + 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rcv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer rcv.Close()
			uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer uc.Close()
			tr := &quic.Transport{Conn: uc}
			f := newFwdBatch(tr, &sendStats{})
			dst := rcv.LocalAddr().(*net.UDPAddr).AddrPort()

			var want [][]byte
			for i := range tc.n {
				b := make([]byte, 1000)
				b[0], b[1] = 0x01, byte(i)
				want = append(want, slices.Clone(b))
				f.add(b, dst)
				// The batch must not keep b.
				clear(b)
			}
			f.flush()
			buf := make([]byte, 2048)
			for i, w := range want {
				require.NoError(t, rcv.SetReadDeadline(time.Now().Add(2*time.Second)))
				n, err := rcv.Read(buf)
				require.NoError(t, err, "packet %d", i)
				assert.Equal(t, w, buf[:n], "packet %d", i)
			}
		})
	}
}
