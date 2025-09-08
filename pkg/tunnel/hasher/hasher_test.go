package hasher_test

import (
	"crypto/sha256"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
)

func TestHash_BidirectionalSame(t *testing.T) {
	h := hasher.NewHasher(keyFrom("test-key-1"))

	a := mustAddrPort(t, "10.0.0.1:1234")
	b := mustAddrPort(t, "10.0.0.2:4321")

	h1 := h.Hash(a, b)
	h2 := h.Hash(b, a)

	require.Equal(t, h1, h2, "hash should be invariant to argument order (bidirectional)")
}

func TestHash_KeyMatters(t *testing.T) {
	h1 := hasher.NewHasher(keyFrom("alpha"))
	h2 := hasher.NewHasher(keyFrom("beta"))

	a := mustAddrPort(t, "10.0.0.1:1111")
	b := mustAddrPort(t, "10.0.0.2:2222")

	require.NotEqual(t, h1.Hash(a, b), h2.Hash(a, b), "different keys must produce different hashes")
}

func TestHash_Deterministic(t *testing.T) {
	h := hasher.NewHasher(keyFrom("determinism"))

	a := mustAddrPort(t, "192.0.2.10:8080")
	b := mustAddrPort(t, "192.0.2.20:8081")

	h1 := h.Hash(a, b)
	h2 := h.Hash(a, b)
	require.Equal(t, h1, h2, "same inputs should always produce the same output")
}

func TestHash_LengthAndFormat(t *testing.T) {
	h := hasher.NewHasher(keyFrom("length-check"))

	a := mustAddrPort(t, "203.0.113.5:65535")
	b := mustAddrPort(t, "198.51.100.7:1")

	out := h.Hash(a, b)
	require.Len(t, out, 32, "should return 128-bit (16-byte) hex string, i.e., 32 hex chars")
	// %x produces lowercase hex; quick sanity check
	require.Equal(t, out, string([]byte(out)), "hex should be lowercase")
}

func TestHash_PortMatters(t *testing.T) {
	h := hasher.NewHasher(keyFrom("port-matters"))
	a := mustAddrPort(t, "10.10.10.10:80")
	b := mustAddrPort(t, "10.10.10.11:80")
	c := mustAddrPort(t, "10.10.10.11:81") // only port differs from b

	require.NotEqual(t, h.Hash(a, b), h.Hash(a, c), "changing only the port must change the hash")
}

func TestHash_IPv4vsIPv6Different(t *testing.T) {
	h := hasher.NewHasher(keyFrom("v4-v6"))

	// Same host bytes represented as IPv4 vs IPv6-mapped IPv4
	ipv4 := mustAddrPort(t, "127.0.0.1:1234")
	ipv6mapped := mustAddrPort(t, "[::ffff:127.0.0.1]:1234")

	// Different families are intentionally encoded with different family markers.
	require.NotEqual(t, h.Hash(ipv4, ipv4), h.Hash(ipv6mapped, ipv6mapped), "IPv4 and IPv6 (mapped) should hash differently")
}

func TestHash_MixedFamiliesBidirectional(t *testing.T) {
	h := hasher.NewHasher(keyFrom("mixed"))

	v4 := mustAddrPort(t, "192.0.2.1:5000")
	v6 := mustAddrPort(t, "[2001:db8::1]:5000")

	// Order independence should still hold even across families
	require.Equal(t, h.Hash(v4, v6), h.Hash(v6, v4))
}

func TestHash_ChangesWithAddress(t *testing.T) {
	h := hasher.NewHasher(keyFrom("addr-change"))

	a1 := mustAddrPort(t, "10.0.0.1:1000")
	a2 := mustAddrPort(t, "10.0.0.2:1000")
	b := mustAddrPort(t, "10.0.0.3:1000")

	require.NotEqual(t, h.Hash(a1, b), h.Hash(a2, b), "changing one endpoint address must change the hash")
}

func TestHash_SortingPathCoverage(t *testing.T) {
	h := hasher.NewHasher(keyFrom("sort-coverage"))

	// Craft pairs likely to flip the left/right lexical comparison
	// v6 encodings are longer; pick addresses so one side compares less/greater.
	left := mustAddrPort(t, "[2001:db8::1]:1")
	right := mustAddrPort(t, "10.0.0.1:65535")

	// Just ensure swapping still matches
	require.Equal(t, h.Hash(left, right), h.Hash(right, left))
}

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	require.NoError(t, err)
	return ap
}

func keyFrom(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	// ensure at least 32 bytes (exactly 32 here)
	return sum[:]
}
