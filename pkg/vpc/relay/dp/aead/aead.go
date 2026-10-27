// SPDX-License-Identifier: AGPL-3.0-only

// Package aead gives the dp.AEAD of the relay programs: AES-GCM of the PSP packets of a batch.
package aead

import (
	"crypto/cipher"
	"fmt"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// GCM is AES-GCM-128 and AES-GCM-256 of PSP, with the Go AES-GCM of softpsp.
type GCM struct{}

var _ dp.AEAD = GCM{}

// NewKey returns the key of a 16 or 32-byte SA key.
func (GCM) NewKey(k []byte) (dp.AEADKey, error) { return psp.NewAEAD(k) }

// Open opens each packet of ops in place and sets its OK. An op that is not valid is a program
// error: Open panics.
func (GCM) Open(mems [][]byte, ops []dp.AEADOp) {
	for i := range ops {
		o := &ops[i]
		pkt := span(mems, o, i, o.Mem, o.Off, o.Len)
		_, err := key(o, i).Open(pkt[psp.PrefixLen:psp.PrefixLen], pkt[4:psp.HeaderLen], pkt[psp.PrefixLen:], pkt[:psp.PrefixLen])
		o.OK = err == nil
	}
}

// Seal seals the text of each op into its packet, after the 24-byte prefix that is in place. An op
// that is not valid is a program error: Seal panics.
func (GCM) Seal(mems [][]byte, ops []dp.AEADOp) {
	for i := range ops {
		o := &ops[i]
		pkt := span(mems, o, i, o.Mem, o.Off, o.Len)
		text := span(mems, o, i, o.SrcMem, o.Src, o.Len-psp.Overhead)
		key(o, i).Seal(pkt[psp.PrefixLen:psp.PrefixLen], pkt[4:psp.HeaderLen], text, pkt[:psp.PrefixLen])
		o.OK = true
	}
}

func key(o *dp.AEADOp, i int) cipher.AEAD {
	k, ok := o.Key.(cipher.AEAD)
	if !ok {
		panic(fmt.Sprintf("aead: op %d has a key of %T", i, o.Key))
	}
	return k
}

// span returns mems[m][off:off+n] of op i, or panics when it is not in the memory or the op is
// shorter than a PSP packet.
func span(mems [][]byte, o *dp.AEADOp, i, m, off, n int) []byte {
	if o.Len < psp.Overhead || m < 0 || m >= len(mems) || off < 0 || n < 0 || n > len(mems[m]) || off > len(mems[m])-n {
		panic(fmt.Sprintf("aead: op %d is not valid: mem %d, off %d, len %d, %d memories", i, m, off, n, len(mems)))
	}
	return mems[m][off : off+n]
}
