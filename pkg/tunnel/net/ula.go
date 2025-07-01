package net

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/netip"

	"github.com/google/uuid"
)

const (
	// Addresses on ApoxyNet overlay follow this format:
	//   fd61:706f:7879:pppp:pppp:eeee:a.b.c.d/128
	// where:
	//  pppp: project ID fnv hash
	//  eeee: endpoint name fnv hash
	//  a.b.c.d: IPv4 address downstream of the tunnel node endpoint
	apoxyULAPrefixS = "fd61:706f:7879::/48"
)

var (
	apoxyULAPrefix = netip.MustParsePrefix(apoxyULAPrefixS)
)

func init() {
	// Ensure that apoxyULAPrefix is exactly 48 bits.
	if apoxyULAPrefix.Bits() != 48 {
		panic("apoxyULAPrefix must be exactly 48 bits")
	}
}

// NetworkIDHexToBytes converts a hexadecimal network id representation to a byte array.
// Example: NetworkIDHexToBytes("12345678") returns [18, 52, 86, 110]
func NetworkIDHexToBytes(h string) ([4]byte, error) {
	if len(h) != 8 {
		return [4]byte{}, fmt.Errorf("hex string must be 8 characters long")
	}

	bs, err := hex.DecodeString(h)
	if err != nil {
		return [4]byte{}, err
	}
	bytes := [4]byte{}
	copy(bytes[:], bs)

	return bytes, nil
}

// ApoxyNetworkULA returns the IPv6 ULA prefix for a project.
func ApoxyNetworkULA(networkID [4]byte) netip.Prefix {
	addr := apoxyULAPrefix.Addr().As16()
	copy(addr[6:], networkID[:])

	return netip.PrefixFrom(netip.AddrFrom16(addr), 96)
}

// NewApoxy4To6Prefix generates a new IPv6 address from the Apoxy4To6Range prefix.
func NewApoxy4To6Prefix(projectID uuid.UUID, endpoint string) netip.Prefix {
	addr := apoxyULAPrefix.Addr().As16()
	p := fnv.New32()
	p.Write(projectID[:])
	copy(addr[6:], p.Sum(nil))

	e := fnv.New32()
	e.Write([]byte(endpoint))
	// We only need 16 bits of the hash so recommendation is to do XOR-folding
	// http://www.isthe.com/chongo/tech/comp/fnv/#xor-fold
	mask := uint32(0xffff)
	h := e.Sum32()>>16 ^ e.Sum32()&mask
	addr[10] = byte(h >> 8)
	addr[11] = byte(h)

	return netip.PrefixFrom(netip.AddrFrom16(addr), 96)
}
