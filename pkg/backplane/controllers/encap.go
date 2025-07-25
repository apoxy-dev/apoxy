package controllers

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const (
	LWTUNNEL_IP_UNSPEC = iota
	LWTUNNEL_IP_ID
	LWTUNNEL_IP_DST
	LWTUNNEL_IP_SRC
	LWTUNNEL_IP_TTL
	LWTUNNEL_IP_TOS
	LWTUNNEL_IP_FLAGS
	LWTUNNEL_IP_PAD
	LWTUNNEL_IP_OPTS
	__LWTUNNEL_IP_MAX
)

// IPEncap represents IP tunnel encapsulation. Implements netlink.Encap interface.
type IPEncap struct {
	ID     uint32 // VNI - Virtual Network Identifier (24 bits)
	Remote net.IP // Remote tunnel endpoint IP address
	TTL    uint8  // Time to live (8 bits)
}

// Type returns the type of the encapsulation (LWTUNNEL_ENCAP_IP).
func (e *IPEncap) Type() int {
	return nl.LWTUNNEL_ENCAP_IP
}

var (
	// native is the native endianness
	native = nl.NativeEndian()
	be     = binary.BigEndian
)

// Decode parses the netlink attributes into the IPEncap structure.
func (e *IPEncap) Decode(buf []byte) error {
	attrs, err := nl.ParseRouteAttr(buf)
	if err != nil {
		return err
	}

	for _, attr := range attrs {
		switch attr.Attr.Type {
		case LWTUNNEL_IP_ID:
			if len(attr.Value) < 4 {
				return fmt.Errorf("geneve: invalid VNI length")
			}
			e.ID = native.Uint32(attr.Value[0:4])
		case LWTUNNEL_IP_DST:
			if len(attr.Value) == 4 {
				e.Remote = net.IP(attr.Value[0:4])
			} else if len(attr.Value) == 16 {
				e.Remote = net.IP(attr.Value[0:16])
			} else {
				return fmt.Errorf("geneve: invalid remote address length")
			}
		}
	}

	return nil
}

// Encode serializes the GeneveEncap structure into netlink attributes
func (e *IPEncap) Encode() ([]byte, error) {
	final := []byte{}

	vniData := make([]byte, 12) // 2+2+8
	native.PutUint16(vniData, 12)
	native.PutUint16(vniData[2:], LWTUNNEL_IP_ID)
	be.PutUint64(vniData[4:], uint64(e.ID))
	final = append(final, vniData...)

	if e.Remote != nil {
		if e.Remote.To4() == nil {
			return nil, fmt.Errorf("geneve: invalid remote address length")
		}

		remoteData := make([]byte, 8) // 2+2+4
		native.PutUint16(remoteData, 8)
		native.PutUint16(remoteData[2:], LWTUNNEL_IP_DST)
		copy(remoteData[4:], e.Remote.To4())
		final = append(final, remoteData...)
	}

	ttl := e.TTL
	if ttl == 0 {
		ttl = 64
	}
	ttlData := make([]byte, 5) // 2+2+1
	native.PutUint16(ttlData, 5)
	native.PutUint16(ttlData[2:], LWTUNNEL_IP_TTL)
	ttlData[4] = ttl
	final = append(final, ttlData...)

	return final, nil
}

// String returns a human-readable representation of the encapsulation.
func (e *IPEncap) String() string {
	return fmt.Sprintf("encap ip id %d dst %s", e.ID, e.Remote)
}

// Equal compares two GeneveEncap instances for equality.
func (e *IPEncap) Equal(x netlink.Encap) bool {
	o, ok := x.(*IPEncap)
	if !ok {
		return false
	}
	if e == o {
		return true
	}
	if e == nil || o == nil {
		return false
	}
	return e.ID == o.ID &&
		((e.Remote == nil && o.Remote == nil) ||
			(e.Remote != nil && o.Remote != nil && e.Remote.Equal(o.Remote)))
}
