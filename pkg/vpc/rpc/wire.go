// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"encoding/binary"
	"io"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/wirepb"
)

// Stream preamble values.
const (
	streamTypeCall  byte = 0x01
	protocolVersion byte = 0x01
)

// Frame kinds.
const (
	frameHeader  byte = 0x01
	frameMessage byte = 0x02
	frameStatus  byte = 0x03
)

const (
	defaultMaxHeaderSize  = 16 << 10
	defaultMaxMessageSize = 4 << 20
	readBufSize           = 4 << 10
	maxPooledBufSize      = 64 << 10
	maxLenVarint          = 5 // Frame lengths are less than 2^32.
)

// frameError is a framing error. The stream is not usable after it.
type frameError struct {
	msg         string
	unsupported bool
}

func (e *frameError) Error() string { return "rpc: " + e.msg }

var (
	errUnsupported   = &frameError{msg: "unsupported stream type or version", unsupported: true}
	errFrameTooLarge = &frameError{msg: "frame too large"}
	errBadLength     = &frameError{msg: "frame length not valid"}
	errBadHeader     = &frameError{msg: "call header not valid"}
	errBadStatus     = &frameError{msg: "status not valid"}
	errUnexpected    = &frameError{msg: "unexpected frame"}
	errNoStatus      = &frameError{msg: "stream ended before the status"}
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, readBufSize); return &b }}

func getBuf() *[]byte { return bufPool.Get().(*[]byte) }

func putBuf(b *[]byte) {
	if cap(*b) > maxPooledBufSize {
		return
	}
	*b = (*b)[:0]
	bufPool.Put(b)
}

var marshalOpts = proto.MarshalOptions{UseCachedSize: true}

// appendFrame appends [kind][len varint][m] to b.
func appendFrame(b []byte, kind byte, m proto.Message, max int) ([]byte, error) {
	n := proto.Size(m)
	if n > max {
		return b, Errorf(ResourceExhausted, "message size %d is more than the limit %d", n, max)
	}
	orig := len(b)
	b = append(b, kind)
	b = binary.AppendUvarint(b, uint64(n))
	b, err := marshalOpts.MarshalAppend(b, m)
	if err != nil {
		return b[:orig], Errorf(Internal, "encode message: %w", err)
	}
	return b, nil
}

// appendCallStart appends the stream preamble and the call header frame to b.
func appendCallStart(b []byte, h *wirepb.CallHeader, max int) ([]byte, error) {
	b = append(b, streamTypeCall, protocolVersion)
	return appendFrame(b, frameHeader, h, max)
}

// frameReader reads frames from a stream through a pooled buffer.
type frameReader struct {
	r    io.Reader
	buf  *[]byte
	b    []byte // Full length view of *buf.
	s, e int    // Unread data is b[s:e].
	err  error  // First read error.
	bad  error  // First frame error; the reader stops after it.
}

func (f *frameReader) init(r io.Reader) {
	f.r = r
	f.buf = getBuf()
	f.b = (*f.buf)[:cap(*f.buf)]
}

func (f *frameReader) release() {
	if f.buf != nil {
		putBuf(f.buf)
		f.buf, f.b = nil, nil
	}
}

// atEOF reports if the peer closed its direction and all data was read.
func (f *frameReader) atEOF() bool { return f.s == f.e && f.err == io.EOF }

// need makes sure that n bytes (n <= len(f.b)) are in the buffer.
func (f *frameReader) need(n int) error {
	for f.e-f.s < n {
		if f.err != nil {
			if f.err == io.EOF && f.e > f.s {
				return io.ErrUnexpectedEOF
			}
			return f.err
		}
		if f.s+n > len(f.b) {
			f.e = copy(f.b, f.b[f.s:f.e])
			f.s = 0
		}
		m, err := f.r.Read(f.b[f.e:])
		f.e += m
		if err != nil {
			f.err = err
		}
	}
	return nil
}

// readFrame reads one frame. A message frame can have msgMax bytes and other
// frames ctlMax bytes. The payload stays valid until the next call. It
// returns io.EOF only when the stream ends at a frame boundary.
func (f *frameReader) readFrame(msgMax, ctlMax int) (kind byte, payload []byte, err error) {
	if f.bad != nil {
		return 0, nil, f.bad
	}
	kind, payload, err = f.next(msgMax, ctlMax)
	if err != nil && err != io.EOF {
		f.bad = err
	}
	return kind, payload, err
}

func (f *frameReader) next(msgMax, ctlMax int) (kind byte, payload []byte, err error) {
	if err := f.need(1); err != nil {
		return 0, nil, err
	}
	max := ctlMax
	if f.b[f.s] == frameMessage {
		max = msgMax
	}
	var l uint64
	var hl int
	for i := 2; ; i++ {
		err := f.need(i)
		if l, hl = binary.Uvarint(f.b[f.s+1 : f.e]); hl > 0 && hl <= maxLenVarint {
			break
		}
		if hl != 0 || i > maxLenVarint {
			return 0, nil, errBadLength
		}
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}
	}
	if l > uint64(max) {
		return 0, nil, errFrameTooLarge
	}
	kind, n, hdr := f.b[f.s], int(l), 1+hl
	if hdr+n <= len(f.b) {
		if err := f.need(hdr + n); err != nil {
			return 0, nil, unexpectedEOF(err)
		}
		payload = f.b[f.s+hdr : f.s+hdr+n]
		f.s += hdr + n
		return kind, payload, nil
	}
	// The frame is larger than the buffer: read it into its own slice.
	payload = make([]byte, n)
	c := copy(payload, f.b[f.s+hdr:f.e])
	f.s, f.e = 0, 0
	if c < n {
		if f.err != nil {
			return 0, nil, unexpectedEOF(f.err)
		}
		if _, err := io.ReadFull(f.r, payload[c:]); err != nil {
			f.err = err
			return 0, nil, unexpectedEOF(err)
		}
	}
	return kind, payload, nil
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// readCallStart reads the stream preamble and the call header.
func readCallStart(f *frameReader, max int) (*wirepb.CallHeader, error) {
	if err := f.need(2); err != nil {
		return nil, unexpectedEOF(err)
	}
	if f.b[f.s] != streamTypeCall || f.b[f.s+1] != protocolVersion {
		return nil, errUnsupported
	}
	f.s += 2
	kind, p, err := f.readFrame(max, max)
	if err != nil {
		return nil, unexpectedEOF(err)
	}
	if kind != frameHeader {
		return nil, errUnexpected
	}
	h := &wirepb.CallHeader{}
	if err := proto.Unmarshal(p, h); err != nil || h.Method == "" || h.TimeoutNs < 0 {
		return nil, errBadHeader
	}
	return h, nil
}

// decodeStatus decodes a status frame payload. It returns nil for OK.
func decodeStatus(p []byte) error {
	var st wirepb.Status
	if err := proto.Unmarshal(p, &st); err != nil {
		return errBadStatus
	}
	if st.Code == uint32(OK) {
		return nil
	}
	return &Error{Code: Code(st.Code), Message: st.Message}
}

// appendStatus appends a status frame for err to b.
func appendStatus(b []byte, err error, max int) []byte {
	c, msg := toStatus(err)
	if len(msg) > max/2 {
		msg = msg[:max/2]
	}
	st := &wirepb.Status{Code: uint32(c), Message: strings.ToValidUTF8(msg, "?")}
	b, _ = appendFrame(b, frameStatus, st, max)
	return b
}
