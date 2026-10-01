// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVNI = 0x123456

// ipPacket returns an IPv4 or IPv6 packet of size bytes from src.
func ipPacket(src netip.Addr, size int) []byte {
	p := make([]byte, size)
	if src.Is4() {
		p[0] = 0x45
		copy(p[12:16], src.AsSlice())
		return p
	}
	p[0] = 0x60
	copy(p[8:24], src.AsSlice())
	return p
}

func TestDataCodec(t *testing.T) {
	cases := []struct {
		name  string
		vni   uint32
		inner string
		wire  string
	}{
		{"packet", testVNI, "hi", "03" + "12345600" + "6869"},
		{"largest VNI", 1<<24 - 1, "hi", "03" + "ffffff00" + "6869"},
		{"VNI zero", 0, "hi", "03" + "00000000" + "6869"},
		{"empty packet", 7, "", "03" + "00000700"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := EncodeData(nil, tc.vni, []byte(tc.inner))
			assert.Equal(t, tc.wire, hex.EncodeToString(b))
			vni, inner, err := DecodeData(b)
			require.NoError(t, err)
			assert.Equal(t, tc.vni, vni)
			assert.Equal(t, tc.inner, string(inner))
		})
	}
}

func TestOpenData(t *testing.T) {
	src4, src6 := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fd00::2")
	other := netip.MustParseAddr("10.0.0.9")
	sources := func(a netip.Addr) bool { return a == src4 || a == src6 }
	withFlags := EncodeData(nil, testVNI, ipPacket(src4, 20))
	withFlags[4] = 0x80
	cases := []struct {
		name  string
		frame []byte
		err   error
	}{
		{"IPv4", EncodeData(nil, testVNI, ipPacket(src4, 20)), nil},
		{"IPv6", EncodeData(nil, testVNI, ipPacket(src6, 40)), nil},
		{"flags are ignored", withFlags, nil},
		{"other VNI", EncodeData(nil, testVNI+1, ipPacket(src4, 20)), ErrVNI},
		{"source of no peer", EncodeData(nil, testVNI, ipPacket(other, 20)), ErrSource},
		{"short IPv4", EncodeData(nil, testVNI, ipPacket(src4, 19)), ErrSource},
		{"short IPv6", EncodeData(nil, testVNI, ipPacket(src6, 39)), ErrSource},
		{"not IP", EncodeData(nil, testVNI, make([]byte, 40)), ErrSource},
		{"empty packet", EncodeData(nil, testVNI, nil), ErrSource},
		{"short frame", EncodeData(nil, testVNI, nil)[:DataLen-1], ErrShort},
		{"peer frame", EncodeFromRelay(nil, src4, ipPacket(src4, 20)), ErrType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner, err := OpenData(tc.frame, testVNI, sources)
			require.ErrorIs(t, err, tc.err)
			if tc.err == nil {
				assert.Equal(t, tc.frame[DataLen:], inner)
			} else {
				assert.Nil(t, inner)
			}
		})
	}
}

// FuzzFrames checks that each frame that a decoder accepts encodes back to the
// same bytes, and that OpenData agrees with DecodeData.
func FuzzFrames(f *testing.F) {
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::2")
	f.Add(EncodeToRelay(nil, dst, src, []byte("hi")))
	f.Add(EncodeFromRelay(nil, src, []byte("hi")))
	f.Add(EncodeData(nil, testVNI, ipPacket(src, 20)))
	f.Add(EncodeData(nil, testVNI, ipPacket(dst, 40)))
	f.Add([]byte{TypeData, 0x12, 0x34, 0x56, 0x80, 0x45})
	allow := func(netip.Addr) bool { return true }
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, s, pkt, err := DecodeToRelay(b); err == nil {
			if got := EncodeToRelay(nil, d, s, pkt); !bytes.Equal(got, b) {
				t.Fatalf("frame to relay %x encodes to %x", b, got)
			}
			if got, want := Forwarded(bytes.Clone(b)), EncodeFromRelay(nil, s, pkt); !bytes.Equal(got, want) {
				t.Fatalf("forwarded %x, want %x", got, want)
			}
		}
		if s, pkt, err := DecodeFromRelay(b); err == nil {
			if got := EncodeFromRelay(nil, s, pkt); !bytes.Equal(got, b) {
				t.Fatalf("frame from relay %x encodes to %x", b, got)
			}
		}
		vni, inner, err := DecodeData(b)
		if err == nil {
			want := bytes.Clone(b)
			want[4] = 0 // EncodeData writes no flags.
			if got := EncodeData(nil, vni, inner); !bytes.Equal(got, want) {
				t.Fatalf("data frame %x encodes to %x", b, got)
			}
		}
		got, oerr := OpenData(b, vni, allow)
		_, isIP := innerSource(inner)
		switch {
		case err != nil && oerr != err:
			t.Fatalf("OpenData error %v, DecodeData error %v", oerr, err)
		case err == nil && isIP != (oerr == nil):
			t.Fatalf("OpenData error %v for inner %x", oerr, inner)
		case oerr == nil && !bytes.Equal(got, inner):
			t.Fatalf("OpenData returned %x, want %x", got, inner)
		}
	})
}

func BenchmarkEncodeData(b *testing.B) {
	inner := ipPacket(netip.MustParseAddr("10.0.0.2"), 1280)
	buf := make([]byte, 0, 2048)
	b.SetBytes(int64(len(inner)))
	b.ReportAllocs()
	for b.Loop() {
		buf = EncodeData(buf[:0], testVNI, inner)
	}
}

func BenchmarkOpenData(b *testing.B) {
	src := netip.MustParseAddr("10.0.0.2")
	frame := EncodeData(nil, testVNI, ipPacket(src, 1280))
	sources := func(a netip.Addr) bool { return a == src }
	b.SetBytes(int64(len(frame) - DataLen))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := OpenData(frame, testVNI, sources); err != nil {
			b.Fatal(err)
		}
	}
}
