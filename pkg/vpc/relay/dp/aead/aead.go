// SPDX-License-Identifier: AGPL-3.0-only

// Package aead is the dp.AEAD of the relay: BoringSSL AES-GCM with one cgo call for each batch. It
// has all cgo and BoringSSL code of the relay, and dp does not import it.
package aead

/*
#cgo CFLAGS: -O2
#cgo noescape aead_open
#cgo nocallback aead_open
#cgo noescape aead_seal
#cgo nocallback aead_seal
#include <stddef.h>
#include <stdint.h>
#include <openssl/aead.h>

// aead_op has no pointer field, so cgocheck does not read it. Go checked each op before the call.
typedef struct {
	uintptr_t ctx;         // EVP_AEAD_CTX *.
	size_t off, len, src;  // The PSP packet is at bases[mem] + off: prefix 24, text, ICV 16.
	uint32_t mem, src_mem; // Seal: the text is at bases[src_mem] + src.
	int32_t ok;
} aead_op;

// The prefix (PSP header and VC) is the AAD. The nonce is bytes 4 to 16 (SPI and IV).
static void aead_open(const uintptr_t *bases, aead_op *ops, size_t n) {
	for (size_t i = 0; i < n; i++) {
		aead_op *o = &ops[i];
		uint8_t *p = (uint8_t *)bases[o->mem] + o->off;
		size_t text = o->len - 40;
		o->ok = EVP_AEAD_CTX_open_gather((const EVP_AEAD_CTX *)o->ctx, p + 24, p + 4, 12,
		                                 p + 24, text, p + 24 + text, 16, p, 24);
	}
}

// The text does not overlap the packet.
static void aead_seal(const uintptr_t *bases, aead_op *ops, size_t n) {
	for (size_t i = 0; i < n; i++) {
		aead_op *o = &ops[i];
		uint8_t *p = (uint8_t *)bases[o->mem] + o->off;
		size_t text = o->len - 40;
		size_t tag_len = 0;
		o->ok = EVP_AEAD_CTX_seal_scatter((const EVP_AEAD_CTX *)o->ctx, p + 24, p + 24 + text,
		                                  &tag_len, 16, p + 4, 12, (const uint8_t *)bases[o->src_mem] + o->src, text,
		                                  NULL, 0, p, 24);
	}
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

const (
	prefixLen = 24 // PSP header and VC: the AAD.
	icvLen    = 16
	overhead  = prefixLen + icvLen
	maxOps    = 64
)

// GCM is BoringSSL AES-GCM with a 16-byte tag. A call pins its Go memories (a pin of C memory, a
// UMEM, does nothing), and it does not allocate when at most five of its memories are Go memory.
type GCM struct{}

var _ dp.AEAD = GCM{}

// key is the context of one SA key in C memory. Only *key goes out of the package (in an AEADKey),
// so each copy of an AEADKey points to the one allocation that has the cleanup.
type key struct{ ctx *C.EVP_AEAD_CTX }

// NewKey returns the context of a key of 16 bytes (AES-128-GCM) or 32 bytes (AES-256-GCM). A GC
// cleanup frees the context when no value refers to the key.
func (GCM) NewKey(k []byte) (dp.AEADKey, error) {
	var a *C.EVP_AEAD
	switch len(k) {
	case 16:
		a = C.EVP_aead_aes_128_gcm()
	case 32:
		a = C.EVP_aead_aes_256_gcm()
	default:
		return nil, fmt.Errorf("aead: a key must be 16 or 32 bytes, not %d", len(k))
	}
	ctx := C.EVP_AEAD_CTX_new(a, (*C.uint8_t)(unsafe.Pointer(&k[0])), C.size_t(len(k)), icvLen)
	if ctx == nil {
		return nil, errors.New("aead: BoringSSL did not make the context")
	}
	p := &key{ctx: ctx}
	runtime.AddCleanup(p, func(ctx *C.EVP_AEAD_CTX) { C.EVP_AEAD_CTX_free(ctx) }, ctx)
	return p, nil
}

// Open opens each packet of ops in place and sets its OK, with one cgo call. An op that is not
// valid or more than 64 ops is a program error: Open panics.
func (GCM) Open(mems [][]byte, ops []dp.AEADOp) { run(mems, ops, false) }

// Seal seals the text of each op after the prefix, which must be in place, with one cgo call, and
// sets OK. A text that overlaps its packet, a bad op, more than 64 ops or a seal failure panics.
func (GCM) Seal(mems [][]byte, ops []dp.AEADOp) { run(mems, ops, true) }

func run(mems [][]byte, ops []dp.AEADOp, seal bool) {
	if len(ops) == 0 {
		return
	}
	if len(ops) > maxOps {
		panic(fmt.Sprintf("aead: %d ops, more than %d", len(ops), maxOps))
	}
	var t bases
	var c [maxOps]C.aead_op
	for i := range ops {
		c[i] = t.check(mems, &ops[i], i, seal)
	}
	// A pin keeps a Go memory in place until Unpin, and Pin makes it escape, so it is not on the
	// stack. C gets addresses with no Go pointer type, so cgocheck does not read the memories.
	var pin runtime.Pinner
	for j, m := range t.mem[:t.n] {
		b := &mems[m][0]
		pin.Pin(b)
		t.addr[j] = C.uintptr_t(uintptr(unsafe.Pointer(b)))
	}
	if seal {
		C.aead_seal(&t.addr[0], &c[0], C.size_t(len(ops)))
	} else {
		C.aead_open(&t.addr[0], &c[0], C.size_t(len(ops)))
	}
	pin.Unpin()
	runtime.KeepAlive(mems)
	for i := range ops {
		ops[i].OK = c[i].ok != 0
		if seal && !ops[i].OK {
			panic(fmt.Sprintf("aead: BoringSSL did not seal op %d", i))
		}
	}
	// The ops hold the keys, so the contexts live until the C call returns.
	runtime.KeepAlive(ops)
}

// bases is the table of the base addresses that C gets: one for each memory that an op uses, at
// most two for each op.
type bases struct {
	n    int
	mem  [2 * maxOps]int // The index in mems of each address.
	addr [2 * maxOps]C.uintptr_t
}

// add returns the table index of mems[m], which is not empty.
func (t *bases) add(m int) C.uint32_t {
	for j := range t.n {
		if t.mem[j] == m {
			return C.uint32_t(j)
		}
	}
	t.mem[t.n] = m
	t.n++
	return C.uint32_t(t.n - 1)
}

// check returns the C form of op i and adds its memories to t. A bad op panics, because C checks
// nothing.
func (t *bases) check(mems [][]byte, o *dp.AEADOp, i int, seal bool) C.aead_op {
	k, _ := o.Key.(*key)
	pkt, ok := span(mems, o.Mem, o.Off, o.Len)
	ok = ok && k != nil && o.Len >= overhead
	var text []byte
	if ok && seal {
		// BoringSSL takes a text and a packet that are the same or apart, and Seal is not in place.
		text, ok = span(mems, o.SrcMem, o.Src, o.Len-overhead)
		ok = ok && !overlap(pkt, text)
	}
	if !ok {
		panic(fmt.Sprintf("aead: op %d is not valid: key %T, mem %d, off %d, len %d, src mem %d, src %d, %d memories",
			i, o.Key, o.Mem, o.Off, o.Len, o.SrcMem, o.Src, len(mems)))
	}
	c := C.aead_op{ctx: C.uintptr_t(uintptr(unsafe.Pointer(k.ctx))), off: C.size_t(o.Off), len: C.size_t(o.Len)}
	c.mem = t.add(o.Mem)
	c.src_mem, c.src = c.mem, c.off // An empty text: BoringSSL reads no byte of it.
	if len(text) > 0 {
		c.src_mem, c.src = t.add(o.SrcMem), C.size_t(o.Src)
	}
	return c
}

// span returns mems[m][off:off+n], or false when it is not in the memory. In this form no sum can
// overflow.
func span(mems [][]byte, m, off, n int) ([]byte, bool) {
	if m < 0 || m >= len(mems) {
		return nil, false
	}
	b := mems[m]
	if off < 0 || n < 0 || n > len(b) || off > len(b)-n {
		return nil, false
	}
	return b[off : off+n], true
}

// overlap tells if a and b share a byte. Two memories can be parts of one buffer, so it compares
// addresses.
func overlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	pa, pb := uintptr(unsafe.Pointer(unsafe.SliceData(a))), uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	return pa < pb+uintptr(len(b)) && pb < pa+uintptr(len(a))
}
