// Package bfdl implements a BFD-lite (RFC 5880 subset) protocol for
// application-level liveness detection between tunnel agents and the
// tunnelproxy server.
package bfdl

import (
	"encoding/binary"
	"fmt"
	"time"
)

// BFDPort is the well-known UDP port for BFD control packets (RFC 5880).
const BFDPort = 3784

// DefaultTxInterval is the interval between BFD control packet transmissions.
// With DetectMult=3, the detect time is 3 × 2s = 6s.
const DefaultTxInterval = 2 * time.Second

// DefaultDetectMult is the number of missed packets before declaring the
// session down.
const DefaultDetectMult = 3

// bfdPacketLen is the fixed length of a BFD control packet.
const bfdPacketLen = 24

// State represents a BFD session state.
type State uint8

const (
	StateAdminDown State = 0
	StateDown      State = 1
	StateInit      State = 2
	StateUp        State = 3
)

func (s State) String() string {
	switch s {
	case StateAdminDown:
		return "AdminDown"
	case StateDown:
		return "Down"
	case StateInit:
		return "Init"
	case StateUp:
		return "Up"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// Packet represents a BFD control packet (RFC 5880 section 4.1).
type Packet struct {
	Version          uint8
	Diag             uint8
	State            State
	Poll             bool
	Final            bool
	DetectMult       uint8
	MyDiscr          uint32
	YourDiscr        uint32
	DesiredMinTx     uint32 // Microseconds.
	RequiredMinRx    uint32 // Microseconds.
	RequiredMinEcho  uint32 // Microseconds, always 0 (no echo mode).
}

// MarshalTo encodes a BFD control packet into buf, which must be at least
// bfdPacketLen (24) bytes. Use with a stack-allocated [bfdPacketLen]byte
// to avoid heap allocation.
//
// Wire format (RFC 5880 section 4.1):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                       My Discriminator                        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                      Your Discriminator                       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Desired Min TX Interval                    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                   Required Min RX Interval                    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                 Required Min Echo RX Interval                 |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func MarshalTo(buf []byte, p *Packet) {
	// Byte 0: Version (3 bits) | Diag (5 bits).
	buf[0] = (p.Version << 5) | (p.Diag & 0x1f)

	// Byte 1: State (2 bits) | P | F | C | A | D | M.
	// C (Control Plane Independent), A (Authentication), D (Demand), M (Multipoint)
	// are always 0 in BFD-lite.
	buf[1] = uint8(p.State) << 6
	if p.Poll {
		buf[1] |= 0x20
	}
	if p.Final {
		buf[1] |= 0x10
	}

	// Byte 2: Detect Multiplier.
	buf[2] = p.DetectMult

	// Byte 3: Length (always 24 for standard BFD).
	buf[3] = bfdPacketLen

	binary.BigEndian.PutUint32(buf[4:8], p.MyDiscr)
	binary.BigEndian.PutUint32(buf[8:12], p.YourDiscr)
	binary.BigEndian.PutUint32(buf[12:16], p.DesiredMinTx)
	binary.BigEndian.PutUint32(buf[16:20], p.RequiredMinRx)
	binary.BigEndian.PutUint32(buf[20:24], p.RequiredMinEcho)
}

// Marshal encodes a BFD control packet into a newly allocated 24-byte slice.
func Marshal(p *Packet) []byte {
	buf := make([]byte, bfdPacketLen)
	MarshalTo(buf, p)
	return buf
}

// UnmarshalInto decodes a BFD control packet from wire format into p.
// Use with a stack-allocated Packet to avoid heap allocation.
func UnmarshalInto(p *Packet, b []byte) error {
	if len(b) < bfdPacketLen {
		return fmt.Errorf("packet too short: %d < %d", len(b), bfdPacketLen)
	}

	p.Version = b[0] >> 5
	p.Diag = b[0] & 0x1f
	p.State = State(b[1] >> 6)
	p.Poll = b[1]&0x20 != 0
	p.Final = b[1]&0x10 != 0
	p.DetectMult = b[2]

	if p.Version != 1 {
		return fmt.Errorf("unsupported BFD version: %d", p.Version)
	}

	length := b[3]
	if length < bfdPacketLen {
		return fmt.Errorf("invalid packet length field: %d", length)
	}

	p.MyDiscr = binary.BigEndian.Uint32(b[4:8])
	p.YourDiscr = binary.BigEndian.Uint32(b[8:12])
	p.DesiredMinTx = binary.BigEndian.Uint32(b[12:16])
	p.RequiredMinRx = binary.BigEndian.Uint32(b[16:20])
	p.RequiredMinEcho = binary.BigEndian.Uint32(b[20:24])

	return nil
}

// Unmarshal decodes a BFD control packet from wire format into a newly
// allocated Packet.
func Unmarshal(b []byte) (*Packet, error) {
	p := &Packet{}
	if err := UnmarshalInto(p, b); err != nil {
		return nil, err
	}
	return p, nil
}
