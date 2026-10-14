package bfdl

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPaddedPduSize checks the padding of RFC 9764 on the send path, and that
// a receiver reads a padded packet.
func TestPaddedPduSize(t *testing.T) {
	cases := []struct {
		name string
		size int
		want int // Length of the packet that the session sends.
	}{
		{name: "no size sends no padding", size: 0, want: bfdPacketLen},
		{name: "padding to the size", size: 1448, want: 1448},
		{name: "size of the packet", size: bfdPacketLen, want: bfdPacketLen},
		{name: "size below the packet sends no padding", size: 10, want: bfdPacketLen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := NewSession(7, DefaultDetectMult, DefaultTxInterval)
			tx.SetPaddedPduSize(tc.size)
			b := tx.AppendTx([]byte{0xaa})
			require.Len(t, b, 1+tc.want)
			assert.Equal(t, byte(0xaa), b[0], "bytes before the packet")
			pkt := b[1:]
			assert.Equal(t, byte(bfdPacketLen), pkt[3], "the Length field counts the padding")
			assert.True(t, bytes.Equal(make([]byte, tc.want-bfdPacketLen), pkt[bfdPacketLen:]), "padding is not zero")

			// Padding that is not zero does not change the result.
			for i := bfdPacketLen; i < len(pkt); i++ {
				pkt[i] = 0xff
			}
			var got Packet
			require.NoError(t, UnmarshalInto(&got, pkt))
			assert.Equal(t, uint32(7), got.MyDiscr)
			rx := NewSession(8, DefaultDetectMult, DefaultTxInterval)
			rx.ProcessRx(&got, nil)
			assert.Equal(t, StateInit, rx.State())
		})
	}
}

// TestUnmarshalLengthAboveSize checks that a packet whose Length field is more
// than its size drops (RFC 5880 section 6.8.6).
func TestUnmarshalLengthAboveSize(t *testing.T) {
	b := Marshal(&Packet{Version: 1, State: StateDown, DetectMult: 3})
	b = append(b, 0, 0)
	b[3] = bfdPacketLen + 4
	_, err := Unmarshal(b)
	assert.Error(t, err)
}
