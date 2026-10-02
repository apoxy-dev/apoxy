// SPDX-License-Identifier: AGPL-3.0-only

package steer

import (
	"testing"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
)

// shortHeader returns a QUIC 1-RTT packet to dcid.
func shortHeader(dcid []byte) []byte {
	p := append([]byte{0x41}, dcid...)
	return append(p, make([]byte, 20)...)
}

// longHeader returns a QUIC v1 Initial packet to dcid.
func longHeader(dcid []byte) []byte {
	p := append([]byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}, dcid...)
	p = append(p, 0) // Source connection ID length.
	return append(p, make([]byte, 20)...)
}

func newVM(t *testing.T, n int) *bpf.VM {
	t.Helper()
	vm, err := bpf.NewVM(Program(n))
	require.NoError(t, err)
	return vm
}

func run(t *testing.T, vm *bpf.VM, pkt []byte) int {
	t.Helper()
	got, err := vm.Run(pkt)
	require.NoError(t, err)
	return got
}

func TestProgram(t *testing.T) {
	const n = 4
	cid := func(first byte) []byte { return []byte{first, 1, 2, 3, 4, 5, 6, 7} }
	psp := func(next byte) []byte { return append([]byte{next, 1, 0x10, 1, 0, 0, 0, 7}, make([]byte, 40)...) }
	cases := []struct {
		name string
		pkt  []byte
		want int
	}{
		{"short header, socket 0", shortHeader(cid(0)), 0},
		{"short header, socket 3", shortHeader(cid(3)), 3},
		{"short header, first byte above n", shortHeader(cid(6)), 2},
		{"long header, socket 1", longHeader(cid(1)), 1},
		{"long header, random client ID", longHeader(cid(0x37)), 3},
		{"long header, 1 B ID", longHeader([]byte{2}), 2},
		{"long header, ID length 0", longHeader(nil), toHash},
		{"long header, no length byte", longHeader(cid(1))[:5], toHash},
		{"long header, no ID byte", longHeader(cid(1))[:6], toHash},
		{"long header, 7 B", longHeader(cid(1))[:7], 1},
		{"short header, 1 B", []byte{0x41}, toHash},
		{"short header, 2 B", []byte{0x41, 2}, 2},
		{"empty", nil, toHash},
		{"PSP in IPv4", psp(pspwire.NextHdrV4), toHash},
		{"PSP in IPv6", psp(pspwire.NextHdrV6), toHash},
		{"path probe", append([]byte{0x02}, make([]byte, 60)...), toHash},
		{"long header with the fixed bit clear", append([]byte{0x80}, longHeader(cid(1))[1:]...), toHash},
	}
	vm := newVM(t, n)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, run(t, vm, tc.pkt))
		})
	}
}

// TestSameConnection checks that the client Initial, and the long and short
// headers to the server ID after it, go to one socket.
func TestSameConnection(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 16, MaxSockets} {
		vm := newVM(t, n)
		for first := range 256 {
			client := []byte{byte(first), 9, 8, 7, 6, 5, 4, 3}
			i := run(t, vm, longHeader(client))
			require.Less(t, i, n)
			server, err := ConnIDs{Index: uint8(i)}.GenerateConnectionID()
			require.NoError(t, err)
			assert.Equal(t, i, run(t, vm, longHeader(server.Bytes())), "n %d, Handshake for client ID %#x", n, first)
			assert.Equal(t, i, run(t, vm, shortHeader(server.Bytes())), "n %d, 1-RTT for client ID %#x", n, first)
		}
	}
}

func TestConnIDs(t *testing.T) {
	g := ConnIDs{Index: 5}
	assert.Equal(t, cidLen, g.ConnectionIDLen())
	seen := map[string]bool{}
	for range 1000 {
		id, err := g.GenerateConnectionID()
		require.NoError(t, err)
		require.Equal(t, cidLen, id.Len())
		assert.Equal(t, byte(5), id.Bytes()[0])
		assert.False(t, seen[id.String()], "repeated ID %s", id)
		seen[id.String()] = true
	}
}

func TestAssemble(t *testing.T) {
	for _, n := range []int{1, 2, MaxSockets} {
		_, err := bpf.Assemble(Program(n))
		assert.NoError(t, err, "n %d", n)
	}
}
