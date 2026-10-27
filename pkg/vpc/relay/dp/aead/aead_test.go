// SPDX-License-Identifier: AGPL-3.0-only

package aead_test

import (
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"slices"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp/aead"
)

// frame is the size of one packet frame in the test memories, and headroom the start of the
// packet in it.
const frame, headroom = 2048, 256

func keyOf(n int, seed byte) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func newKey(t testing.TB, k []byte) dp.AEADKey {
	key, err := aead.GCM{}.NewKey(k)
	require.NoError(t, err)
	return key
}

func goAEAD(t testing.TB, k []byte) cipher.AEAD {
	a, err := psp.NewAEAD(k)
	require.NoError(t, err)
	return a
}

func version(k []byte) psp.Version {
	if len(k) == 32 {
		return psp.AESGCM256
	}
	return psp.AESGCM128
}

// payload returns n random bytes: an IPv4 packet, an IPv6 packet or (kind 2) the payload of a
// trunk, which is not IP.
func payload(r *rand.Rand, n, kind int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	if n > 0 {
		b[0] = [3]byte{0x45, 0x60, 0x10}[kind]
	}
	return b
}

func isIP(p []byte) bool { return len(p) > 0 && (p[0]>>4 == 4 || p[0]>>4 == 6) }

// goSeal seals p with softpsp (Go GCM): with Seal for an IP packet, with SealMessage for a trunk.
func goSeal(t testing.TB, a cipher.AEAD, h psp.Header, p []byte) []byte {
	out := make([]byte, len(p)+psp.Overhead)
	var err error
	if isIP(p) {
		_, err = psp.Seal(a, h, out, p)
	} else {
		_, err = psp.SealMessage(a, h, out, p)
	}
	require.NoError(t, err)
	return out
}

// putPrefix writes the prefix of the PSP packet of p to dst, as the relay does before a seal.
func putPrefix(t testing.TB, h psp.Header, dst, p []byte) {
	switch {
	case len(p) > 0 && p[0]>>4 == 4:
		h.NextHdr = psp.NextHdrV4
	case len(p) > 0 && p[0]>>4 == 6:
		h.NextHdr = psp.NextHdrV6
	default:
		h.NextHdr = psp.NextHdrMessage
	}
	require.NoError(t, psp.PutHeader(h, dst))
}

// opened opens the packets of ops in place as the relay opens a trunk packet: ParseTrunkHeader,
// the Open of GCM, then CheckTrunk. It returns the payload of each packet.
func opened(t testing.TB, mems [][]byte, ops []dp.AEADOp) [][]byte {
	t.Helper()
	for i, o := range ops {
		_, err := psp.ParseTrunkHeader(mems[o.Mem][o.Off : o.Off+o.Len])
		require.NoError(t, err, "packet %d", i)
	}
	aead.GCM{}.Open(mems, ops)
	ps := make([][]byte, len(ops))
	for i, o := range ops {
		require.True(t, o.OK, "packet %d opens", i)
		pkt := mems[o.Mem][o.Off : o.Off+o.Len]
		ps[i] = pkt[psp.PrefixLen : o.Len-psp.ICVLen]
		require.NoError(t, psp.CheckTrunk(pkt, ps[i]), "packet %d", i)
	}
	return ps
}

func unhex(t testing.TB, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestVectors opens PSP packets that the google/psp reference code sealed (from
// interop/testdata/vectors.json of softpsp), and seals their inner packets to the same bytes.
func TestVectors(t *testing.T) {
	cases := []struct {
		name, key, inner, pkt string
	}{
		{
			name:  "AES-128 IPv4",
			key:   "96c22dc799198090b74b70ae468e4e30",
			inner: "4500001c00004000401126cf0a0000010a0000029c40145100080000",
			pkt:   "04020203123456780000000000000001000000000000000043f9f045458355d4b8802b76f54d25b529b0e80d63a0b8d1b91c9dd1ad640c36e3d69bda830131e0b567fee5",
		},
		{
			name:  "AES-128 IPv6",
			key:   "3946da2554eae46ad1ef77a64372edc4",
			inner: "6000000000081140fd000000000000000000000000000001fd0000000000000000000000000000029c40145100080000",
			pkt:   "290202039a3456780000000000000001000000000000000009fb286390667dd6d901d4f2cd2ea1f1cc47a838ba926ddd10e006960bb93f93d0e892e0778b056beffa4b388738267875d114b954bd640a9ff3b6b64b0c1cad",
		},
		{
			name:  "AES-256 IPv4",
			key:   "2b7d72074e42ca334487f2990e3f8c4037e436f38283449b76463e9b7fb2e3de",
			inner: "4500001c00004000401126cf0a0000010a0000029c40145100080000",
			pkt:   "0402020712345678000000000000000100000000000000002527442e407e9f62bb11bd223fd721d18d42225f802317d2f74ae7e96735dd7e91c29a367f9bd6c8761c6189",
		},
		{
			name:  "AES-256 IPv6",
			key:   "fa00f609df6020289a1c93d6027081a637ad45b24a5576b36e6f49dd43114d80",
			inner: "6000000000081140fd000000000000000000000000000001fd0000000000000000000000000000029c40145100080000",
			pkt:   "290202079a345678000000000000000100000000000000007678c9e3d307de883b56029aa139534a3d33d0d92e8023648db9bc679b204952389848bb66ca9e777dffa7d8d481deed968be235b62f4d01961ee6401e6a02fe",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := newKey(t, unhex(t, tc.key))
			inner, want := unhex(t, tc.inner), unhex(t, tc.pkt)

			pkt := slices.Clone(want)
			ops := []dp.AEADOp{{Key: key, Len: len(pkt)}}
			aead.GCM{}.Open([][]byte{pkt}, ops)
			require.True(t, ops[0].OK)
			assert.Equal(t, inner, pkt[psp.PrefixLen:len(pkt)-psp.ICVLen])

			out := make([]byte, len(want))
			copy(out, want[:psp.PrefixLen])
			aead.GCM{}.Seal([][]byte{out, inner}, []dp.AEADOp{{Key: key, Len: len(out), SrcMem: 1}})
			assert.Equal(t, want, out)
		})
	}
}

// TestCross opens 64 Go seals with GCM in place, then seals the texts again with GCM into new
// frames: each must be the Go seal, and Go GCM and GCM must open it.
func TestCross(t *testing.T) {
	sizes := []int{40, 576, 1350, 1500}
	for _, tc := range []struct {
		name string
		mems int
		key  int
	}{
		{"one memory/AES-128", 1, 16},
		{"one memory/AES-256", 1, 32},
		{"two memories/AES-128", 2, 16},
		{"two memories/AES-256", 2, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rand.New(rand.NewPCG(1, uint64(tc.key)))
			k := keyOf(tc.key, 7)
			gcm, key := goAEAD(t, k), newKey(t, k)
			const n = 64
			rx := make([]byte, n*frame)
			tx := rx
			if tc.mems == 2 {
				tx = make([]byte, n*frame)
			} else {
				rx = make([]byte, 2*n*frame)
				tx = rx[n*frame:]
			}
			mems := [][]byte{rx, tx}[:tc.mems]
			ps := make([][]byte, n)
			hs := make([]psp.Header, n)
			sealed := make([][]byte, n)
			ops := make([]dp.AEADOp, n)
			for i := range n {
				ps[i] = payload(r, sizes[i%len(sizes)], i%3)
				hs[i] = psp.Header{Version: version(k), SPI: 0x100 + uint32(i%3), IV: uint64(i), VNI: uint32(i), Flags: psp.FlagSeq, Seq: uint32(i)}
				sealed[i] = goSeal(t, gcm, hs[i], ps[i])
				ops[i] = dp.AEADOp{Key: key, Off: i*frame + headroom, Len: len(sealed[i])}
				copy(rx[ops[i].Off:], sealed[i])
			}

			got := opened(t, mems, ops)
			for i := range ops {
				require.Equal(t, ps[i], got[i], "packet %d", i)
			}

			// The text is in the RX frame, and the packet goes in the TX frame of the same index.
			for i, o := range ops {
				off := i*frame + headroom
				if tc.mems == 1 {
					off += n * frame
				}
				putPrefix(t, hs[i], mems[tc.mems-1][off:], ps[i])
				ops[i] = dp.AEADOp{Key: key, Mem: tc.mems - 1, Off: off, Len: o.Len, Src: o.Off + psp.PrefixLen}
			}
			aead.GCM{}.Seal(mems, ops)
			for i, o := range ops {
				require.True(t, o.OK, "packet %d", i)
				pkt := mems[o.Mem][o.Off : o.Off+o.Len]
				require.Equal(t, sealed[i], pkt, "packet %d: the BoringSSL seal is the Go seal", i)
				// Go GCM opens into a new buffer, so the packet stays for the GCM open.
				text, err := gcm.Open(nil, pkt[4:psp.HeaderLen], pkt[psp.PrefixLen:], pkt[:psp.PrefixLen])
				require.NoError(t, err, "packet %d: Go GCM opens the BoringSSL seal", i)
				require.Equal(t, ps[i], text, "packet %d", i)
			}
			got = opened(t, mems, ops)
			for i := range ops {
				require.Equal(t, ps[i], got[i], "packet %d", i)
			}
		})
	}
}

// TestBatch checks the OK of each op of one Open, and that a Seal of the opened texts gives the
// packets again, which open.
func TestBatch(t *testing.T) {
	k1, k2 := keyOf(16, 1), keyOf(32, 2)
	key1, key2 := newKey(t, k1), newKey(t, k2)
	seal := func(k []byte, seq uint32, n int) []byte {
		r := rand.New(rand.NewPCG(uint64(seq), uint64(n)))
		h := psp.Header{Version: version(k), SPI: 0x100, IV: uint64(seq), Flags: psp.FlagSeq, Seq: seq}
		return goSeal(t, goAEAD(t, k), h, payload(r, n, 2))
	}
	type pkt struct {
		b   []byte
		key dp.AEADKey
	}
	changed := seal(k1, 3, 300)
	changed[psp.PrefixLen+5] ^= 1
	cases := []struct {
		name string
		pkts []pkt
		want []bool
	}{
		{name: "0 ops"},
		{name: "two keys", pkts: []pkt{{seal(k1, 1, 100), key1}, {seal(k2, 1, 200), key2}}, want: []bool{true, true}},
		{name: "one bad packet", pkts: []pkt{{seal(k1, 1, 100), key1}, {changed, key1}, {seal(k1, 2, 50), key1}}, want: []bool{true, false, true}},
		{name: "a wrong key", pkts: []pkt{{seal(k2, 2, 50), key1}, {seal(k1, 2, 50), key1}, {seal(k1, 3, 50), key2}}, want: []bool{false, true, false}},
		{name: "empty text", pkts: []pkt{{seal(k1, 1, 0), key1}, {seal(k2, 1, 0), key2}}, want: []bool{true, true}},
		{name: "64 ops", pkts: func() []pkt {
			var ps []pkt
			for i := range 64 {
				ps = append(ps, pkt{seal(k1, uint32(i), 40+i), key1})
			}
			return ps
		}(), want: slices.Repeat([]bool{true}, 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mem []byte
			var ops []dp.AEADOp
			for i, p := range tc.pkts {
				// Each op starts with the wrong OK, so Open must set each OK.
				ops = append(ops, dp.AEADOp{Key: p.key, Off: len(mem), Len: len(p.b), OK: !tc.want[i]})
				mem = append(mem, p.b...)
			}
			aead.GCM{}.Open([][]byte{mem}, ops)
			var got []bool
			for _, o := range ops {
				got = append(got, o.OK)
			}
			assert.Equal(t, tc.want, got)

			// Seal the opened texts again, into a second memory.
			out := make([]byte, len(mem))
			var seals []dp.AEADOp
			for i, o := range ops {
				if o.OK {
					copy(out[o.Off:], mem[o.Off:o.Off+psp.PrefixLen])
					seals = append(seals, dp.AEADOp{Key: o.Key, Mem: 1, Off: o.Off, Len: o.Len, Src: o.Off + psp.PrefixLen})
				} else {
					copy(out[o.Off:], tc.pkts[i].b)
				}
			}
			aead.GCM{}.Seal([][]byte{mem, out}, seals)
			for _, s := range seals {
				assert.True(t, s.OK)
			}
			want := []byte{}
			for _, p := range tc.pkts {
				want = append(want, p.b...)
			}
			assert.Equal(t, want, out)
			for j, p := range opened(t, [][]byte{mem, out}, seals) {
				assert.Equal(t, mem[seals[j].Src:seals[j].Src+seals[j].Len-psp.Overhead], p, "seal %d", j)
			}
		})
	}
}

// TestBadOps checks that a bad op panics before the C call, so no op of the batch runs. Op 0 of
// each batch is a valid packet in memory 0, after the bad op.
func TestBadOps(t *testing.T) {
	kb := keyOf(16, 1)
	k := newKey(t, kb)
	const memLen = 100
	first := goSeal(t, goAEAD(t, kb), psp.Header{Version: psp.AESGCM128, SPI: 0x100, Flags: psp.FlagSeq}, payload(rand.New(rand.NewPCG(1, 1)), 10, 2))
	// good is in memory 0 before op 0, and its text is in memory 1.
	good := dp.AEADOp{Key: k, Mem: 0, Off: 0, Len: 50, SrcMem: 1, Src: 0}
	with := func(f func(o *dp.AEADOp)) dp.AEADOp {
		o := good
		f(&o)
		return o
	}
	alias := func(m0, _ []byte) [][]byte { return [][]byte{m0, m0} }
	cases := []struct {
		name     string
		op       dp.AEADOp
		ops      int                          // The number of ops; 0 is 2.
		mems     func(m0, m1 []byte) [][]byte // The memories; nil is m0 and m1.
		sealOnly bool                         // Open takes the op.
	}{
		{name: "nil key", op: with(func(o *dp.AEADOp) { o.Key = nil })},
		{name: "other key type", op: with(func(o *dp.AEADOp) { o.Key = "k" })},
		{name: "past the end", op: with(func(o *dp.AEADOp) { o.Off = memLen - 49 })},
		{name: "negative offset", op: with(func(o *dp.AEADOp) { o.Off = -1 })},
		{name: "short", op: with(func(o *dp.AEADOp) { o.Len = 39 })},
		{name: "negative length", op: with(func(o *dp.AEADOp) { o.Len = -1 })},
		{name: "longer than the memory", op: with(func(o *dp.AEADOp) { o.Len = memLen + 1 })},
		{name: "huge offset", op: with(func(o *dp.AEADOp) { o.Off, o.Len = 1<<62+1<<61, 1<<62 })},
		{name: "negative memory index", op: with(func(o *dp.AEADOp) { o.Mem = -1 })},
		{name: "memory index past the end", op: with(func(o *dp.AEADOp) { o.Mem = 2 })},
		{name: "empty memory", op: with(func(o *dp.AEADOp) { o.Mem = 2 }), mems: func(m0, m1 []byte) [][]byte { return [][]byte{m0, m1, nil} }},
		{name: "65 ops", op: good, ops: 65},
		{name: "text past the end", op: with(func(o *dp.AEADOp) { o.Src = memLen - 9 }), sealOnly: true},
		{name: "negative text offset", op: with(func(o *dp.AEADOp) { o.Src = -1 }), sealOnly: true},
		{name: "huge text offset", op: with(func(o *dp.AEADOp) { o.Src = 1<<62 + 1<<61 }), sealOnly: true},
		{name: "negative text memory index", op: with(func(o *dp.AEADOp) { o.SrcMem = -1 }), sealOnly: true},
		{name: "text memory index past the end", op: with(func(o *dp.AEADOp) { o.SrcMem = 2 }), sealOnly: true},
		{name: "text in place", op: with(func(o *dp.AEADOp) { o.SrcMem, o.Src = 0, 24 }), sealOnly: true},
		{name: "text that ends in the packet", op: with(func(o *dp.AEADOp) { o.SrcMem, o.Off, o.Src = 0, 10, 1 }), sealOnly: true},
		{name: "text that starts in the packet", op: with(func(o *dp.AEADOp) { o.SrcMem, o.Off, o.Src = 0, 10, 59 }), sealOnly: true},
		{name: "text in the packet through a second index", op: with(func(o *dp.AEADOp) { o.Src = 5 }), mems: alias, sealOnly: true},
	}
	for _, tc := range cases {
		for _, seal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/seal=%v", tc.name, seal), func(t *testing.T) {
				m0, m1 := make([]byte, memLen), make([]byte, memLen)
				copy(m0[50:], first)
				mems := [][]byte{m0, m1}
				if tc.mems != nil {
					mems = tc.mems(m0, m1)
				}
				ops := []dp.AEADOp{{Key: k, Mem: 0, Off: 50, Len: 50, SrcMem: 1, Src: 0}}
				for len(ops) < max(tc.ops, 2) {
					ops = append(ops, tc.op)
				}
				call := func() { aead.GCM{}.Open(mems, ops) }
				if seal {
					call = func() { aead.GCM{}.Seal(mems, ops) }
				}
				if !seal && tc.sealOnly {
					assert.NotPanics(t, call)
					return
				}
				assert.Panics(t, call)
				assert.Equal(t, first, m0[50:], "op 0 ran")
			})
		}
	}
}

func TestNewKey(t *testing.T) {
	for _, n := range []int{0, 15, 16, 24, 32, 33} {
		_, err := aead.GCM{}.NewKey(make([]byte, n))
		if n == 16 || n == 32 {
			assert.NoError(t, err, "key of %d bytes", n)
		} else {
			assert.Error(t, err, "key of %d bytes", n)
		}
	}
}

// batch64 returns two memories and the Seal ops of 64 packets of 1350 bytes of text: the texts in
// the RX frames of memory 0, and the prefixes in the TX frames of memory 1.
func batch64(t testing.TB, key dp.AEADKey, k []byte) ([][]byte, []dp.AEADOp) {
	const n, size = 64, 1350
	mems := [][]byte{make([]byte, n*frame), make([]byte, n*frame)}
	ops := make([]dp.AEADOp, n)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range ops {
		p := payload(r, size, 0)
		off := i*frame + headroom
		copy(mems[0][off+psp.PrefixLen:], p)
		putPrefix(t, psp.Header{Version: version(k), SPI: 0x100, IV: uint64(i), Flags: psp.FlagSeq, Seq: uint32(i)}, mems[1][off:], p)
		ops[i] = dp.AEADOp{Key: key, Mem: 1, Off: off, Len: size + psp.Overhead, SrcMem: 0, Src: off + psp.PrefixLen}
	}
	return mems, ops
}

// cMem returns n bytes of memory that is not Go memory, as a UMEM is. The kernel gives a page only
// when the test writes it.
func cMem(t *testing.T, n int) []byte {
	b, err := syscall.Mmap(-1, 0, n, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Munmap(b) })
	return b
}

// TestMemories seals 64 texts into packets with GCM and opens them again, in each layout of
// memories. The seals give the Go seal, and a Seal and an Open of 64 packets do not allocate.
func TestMemories(t *testing.T) {
	const n = 64
	goMems := func(count, size int) func(t *testing.T) [][]byte {
		return func(*testing.T) [][]byte {
			ms := make([][]byte, count)
			for i := range ms {
				ms[i] = make([]byte, size)
			}
			return ms
		}
	}
	// at places op i in frame i of a memory: the packet in mems[pm(i)], and the text in mems[sm(i)]
	// at the frame offset plus srcOff.
	at := func(base int, pm, sm func(i int) int, srcOff int) func(i int) (int, int, int, int) {
		return func(i int) (int, int, int, int) {
			off := base + i*frame + headroom
			return pm(i), off, sm(i), off + srcOff
		}
	}
	idx := func(m int) func(int) int { return func(int) int { return m } }
	cases := []struct {
		name  string
		size  int // The text of each packet.
		mems  func(t *testing.T) [][]byte
		place func(i int) (pm, po, sm, so int)
	}{
		{name: "one Go memory", size: 1350, mems: goMems(1, 2*n*frame),
			place: func(i int) (int, int, int, int) { return 0, n*frame + i*frame + headroom, 0, i*frame + headroom }},
		{name: "two Go memories", size: 1350, mems: goMems(2, n*frame), place: at(0, idx(1), idx(0), 0)},
		{name: "a Go memory in a struct with a pointer", size: 1350, mems: func(*testing.T) [][]byte {
			s := &struct {
				p *int
				b [2 * n * frame]byte
			}{p: new(int)}
			return [][]byte{s.b[:]}
		}, place: func(i int) (int, int, int, int) { return 0, n*frame + i*frame + headroom, 0, i*frame + headroom }},
		{name: "five Go memories", size: 1350, mems: goMems(5, n*frame),
			place: at(0, func(i int) int { return i % 5 }, func(i int) int { return (i + 1) % 5 }, 0)},
		{name: "two indexes of one memory", size: 1350, mems: func(*testing.T) [][]byte {
			m := make([]byte, 2*n*frame)
			return [][]byte{m, m}
		}, place: func(i int) (int, int, int, int) { return 1, n*frame + i*frame + headroom, 0, i*frame + headroom }},
		{name: "128 C memories", size: 1350, mems: func(t *testing.T) [][]byte {
			m := cMem(t, 2*n*frame)
			ms := make([][]byte, 2*n)
			for i := range ms {
				ms[i] = m[i*frame : (i+1)*frame]
			}
			return ms
		}, place: func(i int) (int, int, int, int) { return n + i, headroom, i, headroom }},
		{name: "C memory past 4 GiB", size: 1350, mems: func(t *testing.T) [][]byte { return [][]byte{cMem(t, 5<<30)} },
			place: at(4<<30, idx(0), idx(0), -(4 << 30))},
		{name: "empty texts in the packets", size: 0, mems: goMems(1, n*frame), place: func(i int) (int, int, int, int) {
			off := i*frame + headroom
			return 0, off, 0, off + []int{0, psp.PrefixLen, psp.Overhead}[i%3]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := keyOf(32, 5)
			gcm, key := goAEAD(t, k), newKey(t, k)
			mems := tc.mems(t)
			r := rand.New(rand.NewPCG(3, 4))
			ps, want := make([][]byte, n), make([][]byte, n)
			seals, opens := make([]dp.AEADOp, n), make([]dp.AEADOp, n)
			for i := range n {
				pm, po, sm, so := tc.place(i)
				ps[i] = payload(r, tc.size, i%3)
				h := psp.Header{Version: psp.AESGCM256, SPI: 0x100, IV: uint64(i), Flags: psp.FlagSeq, Seq: uint32(i)}
				want[i] = goSeal(t, gcm, h, ps[i])
				copy(mems[sm][so:], ps[i])
				putPrefix(t, h, mems[pm][po:], ps[i])
				seals[i] = dp.AEADOp{Key: key, Mem: pm, Off: po, Len: len(want[i]), SrcMem: sm, Src: so}
				opens[i] = dp.AEADOp{Key: key, Mem: pm, Off: po, Len: len(want[i])}
			}
			aead.GCM{}.Seal(mems, seals)
			for i, o := range seals {
				require.Equal(t, want[i], mems[o.Mem][o.Off:o.Off+o.Len], "packet %d: the BoringSSL seal is the Go seal", i)
			}
			allocs := testing.AllocsPerRun(10, func() {
				aead.GCM{}.Seal(mems, seals)
				aead.GCM{}.Open(mems, opens)
			})
			assert.Zero(t, allocs)
			for i, o := range opens {
				require.True(t, o.OK, "packet %d opens", i)
				require.Equal(t, ps[i], mems[o.Mem][o.Off+psp.PrefixLen:o.Off+o.Len-psp.ICVLen], "packet %d", i)
			}
		})
	}
}

// BenchmarkGCM compares GCM with Go GCM on 64 packets of 1350 bytes of text: Seal from the RX into
// the TX frames, and Open in place after a copy of the sealed packets, for both.
func BenchmarkGCM(b *testing.B) {
	for _, kl := range []int{16, 32} {
		k := keyOf(kl, 9)
		gcm := goAEAD(b, k)
		mems, ops := batch64(b, newKey(b, k), k)
		aead.GCM{}.Seal(mems, ops)
		sealed := slices.Clone(mems[1])
		opens := make([]dp.AEADOp, len(ops))
		for i, o := range ops {
			opens[i] = dp.AEADOp{Key: o.Key, Mem: 1, Off: o.Off, Len: o.Len}
		}
		cases := []struct {
			name string
			run  func()
		}{
			{"seal/boringssl", func() { aead.GCM{}.Seal(mems, ops) }},
			{"seal/go", func() {
				for _, o := range ops {
					pkt := mems[1][o.Off : o.Off+o.Len]
					gcm.Seal(pkt[psp.PrefixLen:psp.PrefixLen], pkt[4:psp.HeaderLen], mems[0][o.Src:o.Src+o.Len-psp.Overhead], pkt[:psp.PrefixLen])
				}
			}},
			{"open/boringssl", func() { copy(mems[1], sealed); aead.GCM{}.Open(mems, opens) }},
			{"open/go", func() {
				copy(mems[1], sealed)
				for _, o := range opens {
					pkt := mems[1][o.Off : o.Off+o.Len]
					if _, err := psp.OpenInPlace(gcm, pkt); err != nil {
						b.Fatal(err)
					}
				}
			}},
		}
		for _, tc := range cases {
			b.Run(fmt.Sprintf("AES-%d/%s", kl*8, tc.name), func(b *testing.B) {
				b.SetBytes(int64(len(ops) * 1350))
				for b.Loop() {
					tc.run()
				}
			})
		}
	}
}
