// SPDX-License-Identifier: AGPL-3.0-only

package dp

type AEAD interface { // Hand-written. The relay programs give aead.GCM.
	NewKey(key []byte) (AEADKey, error)
	Open(mems [][]byte, ops []AEADOp) // In place. At most 64 ops; sets OK.
	Seal(mems [][]byte, ops []AEADOp) // From the text into the packet.
}

// AEADKey is the context of one SA key, from NewKey of the same AEAD.
type AEADKey any

type AEADOp struct {
	Key           AEADKey
	Mem, Off, Len int // mems[Mem][Off:Off+Len]: PSP header to the end of the ICV.
	SrcMem, Src   int // Seal: the text is mems[SrcMem][Src:Src+Len-40].
	OK            bool
}
