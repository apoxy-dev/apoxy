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

// Marshal encodes a BFD control packet into a 24-byte wire format.
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
func Marshal(p *Packet) []byte {
	buf := make([]byte, bfdPacketLen)

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

	return buf
}

// Unmarshal decodes a BFD control packet from wire format.
func Unmarshal(b []byte) (*Packet, error) {
	if len(b) < bfdPacketLen {
		return nil, fmt.Errorf("packet too short: %d < %d", len(b), bfdPacketLen)
	}

	p := &Packet{
		Version:    b[0] >> 5,
		Diag:       b[0] & 0x1f,
		State:      State(b[1] >> 6),
		Poll:       b[1]&0x20 != 0,
		Final:      b[1]&0x10 != 0,
		DetectMult: b[2],
	}

	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported BFD version: %d", p.Version)
	}

	length := b[3]
	if length < bfdPacketLen {
		return nil, fmt.Errorf("invalid packet length field: %d", length)
	}

	p.MyDiscr = binary.BigEndian.Uint32(b[4:8])
	p.YourDiscr = binary.BigEndian.Uint32(b[8:12])
	p.DesiredMinTx = binary.BigEndian.Uint32(b[12:16])
	p.RequiredMinRx = binary.BigEndian.Uint32(b[16:20])
	p.RequiredMinEcho = binary.BigEndian.Uint32(b[20:24])

	return p, nil
}
