// SPDX-License-Identifier: AGPL-3.0-only

// Package steer sends each QUIC packet of a relay to the socket that has its
// connection. The transport on socket i issues connection IDs that start with i.
package steer

import (
	"crypto/rand"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/bpf"
)

const (
	// cidLen is the length of the connection IDs: the index and 7 random bytes.
	cidLen = 8
	// MaxSockets is the most sockets in a group. The index is one byte.
	MaxSockets = 256
	// toHash is an index past the group, so the kernel uses its 4-tuple hash.
	toHash = 0xffffffff
)

// ConnIDs is the quic.ConnectionIDGenerator of the transport on socket Index.
type ConnIDs struct {
	Index uint8
}

func (g ConnIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	var b [cidLen]byte
	b[0] = g.Index
	_, _ = rand.Read(b[1:])
	return quic.ConnectionIDFromBytes(b[:]), nil
}

func (ConnIDs) ConnectionIDLen() int { return cidLen }

// Program returns the classic BPF program of a group of n sockets: a QUIC
// packet goes to socket dcid[0] mod n, and other packets get the 4-tuple hash.
func Program(n int) []bpf.Instruction {
	return []bpf.Instruction{
		// The kernel gives the program the UDP payload.
		bpf.LoadExtension{Num: bpf.ExtLen},
		bpf.JumpIf{Cond: bpf.JumpLessThan, Val: 2, SkipTrue: 13},
		bpf.LoadAbsolute{Off: 0, Size: 1},
		// PSP and probes have the QUIC fixed bit clear.
		bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 0x40, SkipTrue: 11},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x80, SkipTrue: 3},
		// Short header: the connection ID starts at byte 1.
		bpf.LoadAbsolute{Off: 1, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpMod, Val: uint32(n)},
		bpf.RetA{},
		// Long header: the connection ID length is at byte 5, the ID at byte 6.
		bpf.LoadExtension{Num: bpf.ExtLen},
		bpf.JumpIf{Cond: bpf.JumpLessThan, Val: 7, SkipTrue: 5},
		bpf.LoadAbsolute{Off: 5, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 3},
		bpf.LoadAbsolute{Off: 6, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpMod, Val: uint32(n)},
		bpf.RetA{},
		bpf.RetConstant{Val: toHash},
	}
}
