// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"errors"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/wirepb"
)

const fuzzMax = 512

func fuzzSeeds(f *testing.F) {
	start, _ := appendCallStart(nil, &wirepb.CallHeader{Method: "/a.B/C", TimeoutNs: 1e9, Metadata: map[string]string{"k": "v"}}, fuzzMax)
	msg, _ := appendFrame(nil, frameMessage, &wirepb.CallHeader{Method: "payload"}, fuzzMax)
	st := appendStatus(nil, Errorf(NotFound, "x"), fuzzMax)
	for _, s := range [][]byte{
		nil,
		start,
		append(append(append([]byte{}, start...), msg...), st...),
		msg,
		st,
		{streamTypeCall, protocolVersion, frameHeader, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01},
		{streamTypeCall, protocolVersion, frameHeader, 0xff, 0xff, 0xff, 0xff, 0x0f},
		{0x02, 0x01},
		{frameStatus, 2, 0x08, 0xff},
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
}

// FuzzReadCallStart checks the preamble and call header decoder.
func FuzzReadCallStart(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte, oneByte bool) {
		r := newReader(data, oneByte)
		defer r.release()
		h, err := readCallStart(r, fuzzMax)
		if err != nil {
			var fe *frameError
			if !errors.As(err, &fe) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("unexpected error type %T: %v", err, err)
			}
			return
		}
		if h.Method == "" || h.TimeoutNs < 0 {
			t.Fatalf("header not valid: %v", h)
		}
		b, err := appendCallStart(nil, h, fuzzMax+64)
		if err != nil {
			t.Fatal(err)
		}
		r2 := newReader(b, false)
		defer r2.release()
		h2, err := readCallStart(r2, fuzzMax+64)
		if err != nil || !proto.Equal(h, h2) {
			t.Fatalf("round trip: %v %v %v", h, h2, err)
		}
	})
}

// FuzzReadFrames checks the frame decoder and the status decoder.
func FuzzReadFrames(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte, oneByte bool) {
		r := newReader(data, oneByte)
		defer r.release()
		total := 0
		for {
			kind, p, err := r.readFrame(fuzzMax, fuzzMax)
			if err != nil {
				return
			}
			if len(p) > fuzzMax {
				t.Fatalf("payload of %d bytes is more than the limit", len(p))
			}
			if total += 2 + len(p); total > len(data) {
				t.Fatalf("read %d bytes from %d", total, len(data))
			}
			if kind == frameStatus {
				_ = decodeStatus(p)
			}
		}
	})
}

// FuzzDecodeStatus checks that a decoded status encodes to the same status.
func FuzzDecodeStatus(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x05, 0x12, 0x01, 'x'})
	f.Add([]byte{0x08, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add([]byte{0x12, 0x02, 0xff, 0xfe})
	f.Fuzz(func(t *testing.T, p []byte) {
		err := decodeStatus(p)
		var e *Error
		if err == nil || !errors.As(err, &e) {
			return
		}
		if e.Code == OK {
			t.Fatal("error with code OK")
		}
		r := newReader(appendStatus(nil, e, 1<<20), false)
		defer r.release()
		_, p2, rerr := r.readFrame(1<<20, 1<<20)
		if rerr != nil {
			t.Fatal(rerr)
		}
		var e2 *Error
		if !errors.As(decodeStatus(p2), &e2) || e2.Code != e.Code || e2.Message != e.Message {
			t.Fatalf("round trip: %v %v", e, e2)
		}
	})
}
