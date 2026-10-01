// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodec(t *testing.T) {
	addr := netip.MustParseAddr
	cases := []struct {
		name     string
		dst, src netip.Addr
		pkt      string
		toRelay  string // Hex of the frame from the agent.
	}{
		{
			name: "IPv6", dst: addr("fd00::2"), src: addr("fd00::1"), pkt: "hi",
			toRelay: "01" + "fd000000000000000000000000000002" + "fd000000000000000000000000000001" + "6869",
		},
		{
			name: "IPv4 is 4-in-6", dst: addr("10.0.0.2"), src: addr("10.0.0.1"), pkt: "hi",
			toRelay: "01" + "00000000000000000000ffff0a000002" + "00000000000000000000ffff0a000001" + "6869",
		},
		{
			name: "empty packet", dst: addr("fd00::2"), src: addr("10.0.0.1"),
			toRelay: "01" + "fd000000000000000000000000000002" + "00000000000000000000ffff0a000001",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := EncodeToRelay(nil, tc.dst, tc.src, []byte(tc.pkt))
			assert.Equal(t, tc.toRelay, hex.EncodeToString(up))
			dst, src, pkt, err := DecodeToRelay(up)
			require.NoError(t, err)
			assert.Equal(t, tc.dst, dst)
			assert.Equal(t, tc.src, src)
			assert.Equal(t, tc.pkt, string(pkt))

			down := EncodeFromRelay(nil, tc.src, []byte(tc.pkt))
			assert.Equal(t, tc.toRelay[:2]+tc.toRelay[2+32:], hex.EncodeToString(down))
			src, pkt, err = DecodeFromRelay(down)
			require.NoError(t, err)
			assert.Equal(t, tc.src, src)
			assert.Equal(t, tc.pkt, string(pkt))

			assert.Equal(t, down, Forwarded(up))
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	up := EncodeToRelay(nil, netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::1"), nil)
	down := EncodeFromRelay(nil, netip.MustParseAddr("fd00::1"), nil)
	cases := []struct {
		name               string
		b                  []byte
		toRelay, fromRelay error
	}{
		{"empty", nil, ErrShort, ErrShort},
		{"short", up[:ToRelayLen-1], ErrShort, nil},
		{"short from relay", down[:FromRelayLen-1], ErrShort, ErrShort},
		{"probe", append([]byte{TypeProbe}, up[1:]...), ErrType, ErrType},
		{"data", append([]byte{TypeData}, up[1:]...), ErrType, ErrType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// errors.Is(err, nil) is true only when err is nil.
			_, _, _, err := DecodeToRelay(tc.b)
			assert.ErrorIs(t, err, tc.toRelay)
			_, _, err = DecodeFromRelay(tc.b)
			assert.ErrorIs(t, err, tc.fromRelay)
		})
	}
}
