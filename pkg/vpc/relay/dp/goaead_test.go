// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"crypto/cipher"

	"github.com/apoxy-dev/softpsp/psp"
)

// goAEAD is the AEAD of the tests of package dp: the Go AES-GCM of softpsp. These tests cannot
// import package aead, because aead imports dp. The tests of package dp_test use aead.GCM.
type goAEAD struct{}

func (goAEAD) NewKey(k []byte) (AEADKey, error) { return psp.NewAEAD(k) }

func (goAEAD) Open(mems [][]byte, ops []AEADOp) {
	for i := range ops {
		o := &ops[i]
		pkt := mems[o.Mem][o.Off : o.Off+o.Len]
		_, err := o.Key.(cipher.AEAD).Open(pkt[psp.PrefixLen:psp.PrefixLen], pkt[4:psp.HeaderLen], pkt[psp.PrefixLen:], pkt[:psp.PrefixLen])
		o.OK = err == nil
	}
}

func (goAEAD) Seal(mems [][]byte, ops []AEADOp) {
	for i := range ops {
		o := &ops[i]
		pkt := mems[o.Mem][o.Off : o.Off+o.Len]
		text := mems[o.SrcMem][o.Src : o.Src+o.Len-psp.Overhead]
		o.Key.(cipher.AEAD).Seal(pkt[psp.PrefixLen:psp.PrefixLen], pkt[4:psp.HeaderLen], text, pkt[:psp.PrefixLen])
		o.OK = true
	}
}
