// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/wirepb"
)

func newReader(data []byte, oneByte bool) *frameReader {
	var r io.Reader = bytes.NewReader(data)
	if oneByte {
		r = iotest.OneByteReader(r)
	}
	f := &frameReader{}
	f.init(r)
	return f
}

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		sizes []int
	}{
		{"empty", []int{0}},
		{"small", []int{1, 10, 100}},
		{"buffer size", []int{readBufSize - 8, readBufSize - 3, readBufSize, readBufSize + 1}},
		{"large", []int{100 << 10, 1, 300 << 10}},
	}
	for _, tc := range cases {
		for _, oneByte := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				var b []byte
				var want [][]byte
				for i, n := range tc.sizes {
					m := wrapperspb.Bytes(bytes.Repeat([]byte{byte(i + 1)}, n))
					var err error
					b, err = appendFrame(b, frameMessage, m, 1<<20)
					require.NoError(t, err)
					enc, _ := proto.Marshal(m)
					want = append(want, enc)
				}
				f := newReader(b, oneByte)
				defer f.release()
				for _, w := range want {
					kind, p, err := f.readFrame(1<<20, 1<<20)
					require.NoError(t, err)
					assert.Equal(t, frameMessage, kind)
					assert.Equal(t, w, p)
				}
				_, _, err := f.readFrame(1<<20, 1<<20)
				assert.Equal(t, io.EOF, err)
				assert.True(t, f.atEOF())
			})
		}
	}
}

func TestReadFrameErrors(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		max  int
		want error
	}{
		{"eof at boundary", nil, 100, io.EOF},
		{"kind only", []byte{frameMessage}, 100, io.ErrUnexpectedEOF},
		{"varint not complete", []byte{frameMessage, 0x80}, 100, io.ErrUnexpectedEOF},
		{"varint too long", []byte{frameMessage, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 100, errBadLength},
		{"varint overflow", append([]byte{frameMessage}, bytes.Repeat([]byte{0xff}, 11)...), 100, errBadLength},
		{"too large", []byte{frameMessage, 101}, 100, errFrameTooLarge},
		{"payload not complete", []byte{frameMessage, 3, 1, 2}, 100, io.ErrUnexpectedEOF},
		{"large payload not complete", append([]byte{frameMessage, 0x80, 0x40}, make([]byte, 5000)...), 1 << 20, io.ErrUnexpectedEOF},
	}
	for _, tc := range cases {
		for _, oneByte := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				f := newReader(tc.data, oneByte)
				defer f.release()
				_, _, err := f.readFrame(tc.max, tc.max)
				assert.ErrorIs(t, err, tc.want)
				_, _, err = f.readFrame(tc.max, tc.max)
				assert.ErrorIs(t, err, tc.want, "second read")
			})
		}
	}
}

func TestReadCallStart(t *testing.T) {
	valid := func(h *wirepb.CallHeader) []byte {
		b, err := appendCallStart(nil, h, 1<<20)
		require.NoError(t, err)
		return b
	}
	withPreamble := func(b ...byte) []byte { return append([]byte{streamTypeCall, protocolVersion}, b...) }
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"valid", valid(&wirepb.CallHeader{Method: "/a.B/C", TimeoutNs: 5, Metadata: map[string]string{"k": "v"}}), nil},
		{"empty", nil, io.ErrUnexpectedEOF},
		{"type only", []byte{streamTypeCall}, io.ErrUnexpectedEOF},
		{"unknown type", []byte{0x02, protocolVersion}, errUnsupported},
		{"unknown version", []byte{streamTypeCall, 0x02}, errUnsupported},
		{"no header", withPreamble(), io.ErrUnexpectedEOF},
		{"wrong kind", withPreamble(frameMessage, 0), errUnexpected},
		{"bad protobuf", withPreamble(frameHeader, 2, 0xff, 0xff), errBadHeader},
		{"empty method", withPreamble(frameHeader, 0), errBadHeader},
		{"negative timeout", valid(&wirepb.CallHeader{Method: "/a.B/C", TimeoutNs: -1}), errBadHeader},
		{"header too large", valid(&wirepb.CallHeader{Method: "/" + strings.Repeat("x", 2000)}), errFrameTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newReader(tc.data, false)
			defer f.release()
			h, err := readCallStart(f, 1<<10)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "/a.B/C", h.Method)
		})
	}
}

func TestStatusRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode Code
		wantMsg  string
	}{
		{"ok", nil, OK, ""},
		{"rpc error", Errorf(NotFound, "no peer %d", 7), NotFound, "no peer 7"},
		{"plain error", errors.New("boom"), Unknown, "boom"},
		{"invalid utf-8", Errorf(Internal, "bad \xff"), Internal, "bad ?"},
		{"long message", Errorf(Internal, "%s", strings.Repeat("a", 1000)), Internal, strings.Repeat("a", 256)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newReader(appendStatus(nil, tc.err, 512), false)
			defer f.release()
			kind, p, err := f.readFrame(512, 512)
			require.NoError(t, err)
			require.Equal(t, frameStatus, kind)
			got := decodeStatus(p)
			if tc.wantCode == OK {
				assert.NoError(t, got)
				return
			}
			var e *Error
			require.ErrorAs(t, got, &e)
			assert.Equal(t, tc.wantCode, e.Code)
			assert.Equal(t, tc.wantMsg, e.Message)
		})
	}
}
