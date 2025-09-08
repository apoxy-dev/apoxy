package adapter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/netip"
)

// Hasher generates a unique, consistent ID for a pair of addresses.
type Hasher struct {
	idKey []byte // atleast 32 bytes of random data
}

func NewHasher(idKey []byte) *Hasher {
	return &Hasher{
		idKey: idKey,
	}
}

func (h *Hasher) Hash(localAddr, remoteAddr netip.AddrPort) string {
	encode := func(ap netip.AddrPort) []byte {
		var b []byte
		addr := ap.Addr()
		if addr.Is4() {
			b = append(b, 4) // family marker
			a := addr.As4()
			b = append(b, a[:]...)
		} else {
			b = append(b, 6) // family marker
			a := addr.As16()
			b = append(b, a[:]...)
		}
		p := ap.Port()
		b = append(b, byte(p>>8), byte(p)) // big-endian port
		return b
	}

	left := encode(localAddr)
	right := encode(remoteAddr)

	// Sort the pair so IDs are bidirectional.
	var data []byte
	if bytes.Compare(left, right) < 0 {
		data = append(left, right...)
	} else {
		data = append(right, left...)
	}

	mac := hmac.New(sha256.New, h.idKey)
	mac.Write(data)
	sum := mac.Sum(nil)

	// Return 128-bit hex string for compactness
	return fmt.Sprintf("%x", sum[:16])
}
