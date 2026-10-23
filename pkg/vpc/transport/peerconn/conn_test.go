// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordHandler is a DataHandler that keeps the payload of each data frame and an "end" for each
// BatchEnd. onData runs before it keeps a frame.
type recordHandler struct {
	mu     sync.Mutex
	events []string
	onData func()
}

func (h *recordHandler) HandleData(frame []byte) {
	if h.onData != nil {
		h.onData()
	}
	_, inner, err := DecodeData(frame)
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		h.events = append(h.events, "bad frame")
		return
	}
	h.events = append(h.events, string(inner))
}

func (h *recordHandler) BatchEnd() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, "end")
}

func (h *recordHandler) got() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.events)
}

// TestReceive gives reads of frames to the reader of the session connection. The data frames of
// a read go to the data handler, then its BatchEnd runs. The other frames drop and count.
func TestReceive(t *testing.T) {
	data := func(s string) []byte { return EncodeData(nil, testVNI, []byte(s)) }
	peer := EncodeFromRelay(nil, netip.MustParseAddr("fd00::2"), []byte("peer"))
	cases := []struct {
		name    string
		handler bool
		unset   bool // The handler stops itself at its first frame.
		reads   [][][]byte
		want    []string
		drops   uint64
	}{
		{name: "data frame", handler: true, reads: [][][]byte{{data("a")}}, want: []string{"a", "end"}},
		{name: "data and peer frames", handler: true, reads: [][][]byte{{data("a"), data("b"), peer, data("c")}},
			want: []string{"a", "b", "c", "end"}, drops: 1},
		{name: "two reads", handler: true, reads: [][][]byte{{data("a")}, {data("b"), data("c")}},
			want: []string{"a", "end", "b", "c", "end"}},
		{name: "no handler", reads: [][][]byte{{data("a"), data("b")}}, drops: 2},
		{name: "empty frame", handler: true, reads: [][][]byte{{{}}}, want: []string{"end"}, drops: 1},
		{name: "handler stops during a read", handler: true, unset: true,
			reads: [][][]byte{{data("a"), data("b")}, {data("c")}}, want: []string{"a", "b", "end"}, drops: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qc := newFakeQC()
			c := New(qc)
			defer c.Close()
			h := &recordHandler{}
			if tc.unset {
				h.onData = func() { c.HandleData(nil) }
			}
			if tc.handler {
				c.HandleData(h)
			}
			for _, r := range tc.reads {
				qc.in <- r
			}
			require.Eventually(t, func() bool {
				return slices.Equal(tc.want, h.got()) && c.Stats().OtherDrops == tc.drops
			}, 5*time.Second, time.Millisecond, "events %q, stats %+v", h.got(), c.Stats())
		})
	}
}

// exitQC is a fakeQC that closes exited when the reader gets an error.
type exitQC struct {
	*fakeQC
	exited chan struct{}
}

func (q *exitQC) ReceiveDatagrams(ctx context.Context, bufs [][]byte) (int, error) {
	if ctx.Err() == nil {
		if n, err := q.fakeQC.ReceiveDatagrams(ctx, bufs); err == nil {
			return n, nil
		}
	}
	close(q.exited)
	return 0, ctx.Err()
}

// handlerFunc is a DataHandler that gives each frame to a function.
type handlerFunc func([]byte)

func (h handlerFunc) HandleData(frame []byte) { h(frame) }
func (handlerFunc) BatchEnd()                 {}

// TestCloseDoesNotWait checks that Close returns while the handler holds a
// frame, and that the reader exits after the handler returns.
func TestCloseDoesNotWait(t *testing.T) {
	qc := &exitQC{fakeQC: newFakeQC(), exited: make(chan struct{})}
	c := New(qc)
	in, release := make(chan struct{}), make(chan struct{})
	c.HandleData(handlerFunc(func([]byte) {
		close(in)
		<-release
	}))
	qc.in <- [][]byte{EncodeData(nil, testVNI, []byte("held"))}
	<-in
	closed := make(chan struct{})
	go func() {
		_ = c.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited for the handler")
	}
	select {
	case <-qc.exited:
		t.Fatal("the reader exited while the handler held the frame")
	default:
	}
	close(release)
	select {
	case <-qc.exited:
	case <-time.After(time.Second):
		t.Fatal("the reader did not exit after the release")
	}
	assert.ErrorIs(t, c.SendData(EncodeData(nil, testVNI, nil)), net.ErrClosed)
}
