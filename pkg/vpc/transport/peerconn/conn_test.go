// SPDX-License-Identifier: AGPL-3.0-only

package peerconn

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReceive checks which frames of the session connection go to the data
// handler, and which drop and count.
func TestReceive(t *testing.T) {
	data := EncodeData(nil, testVNI, []byte("data"))
	peer := EncodeFromRelay(nil, netip.MustParseAddr("fd00::2"), []byte("peer"))
	cases := []struct {
		name    string
		handler bool
		frame   []byte
		got     bool // The handler got the frame.
		drops   uint64
	}{
		{name: "data frame", handler: true, frame: data, got: true},
		{name: "peer frame", handler: true, frame: peer, drops: 1},
		{name: "data frame and no handler", frame: data, drops: 1},
		{name: "empty frame", handler: true, frame: []byte{}, drops: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qc := newFakeQC()
			c := New(qc)
			defer c.Close()
			got := make(chan []byte, 2)
			if tc.handler {
				c.HandleData(func(b []byte) { got <- bytes.Clone(b) })
			}
			qc.in <- tc.frame
			if tc.got {
				select {
				case b := <-got:
					assert.Equal(t, tc.frame, b)
				case <-time.After(5 * time.Second):
					t.Fatal("the handler did not get the frame")
				}
			} else {
				require.Eventually(t, func() bool { return c.Stats().OtherDrops == tc.drops }, 5*time.Second, time.Millisecond)
			}
			assert.Empty(t, got)
			assert.Equal(t, Stats{OtherDrops: tc.drops}, c.Stats())
		})
	}
}

// exitQC is a fakeQC that closes exited when the reader gets an error.
type exitQC struct {
	*fakeQC
	exited chan struct{}
}

func (q *exitQC) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if ctx.Err() == nil {
		if b, err := q.fakeQC.ReceiveDatagram(ctx); err == nil {
			return b, nil
		}
	}
	close(q.exited)
	return nil, ctx.Err()
}

// TestCloseDoesNotWait checks that Close returns while the handler holds a
// frame, and that the reader exits after the handler returns.
func TestCloseDoesNotWait(t *testing.T) {
	qc := &exitQC{fakeQC: newFakeQC(), exited: make(chan struct{})}
	c := New(qc)
	in, release := make(chan struct{}), make(chan struct{})
	c.HandleData(func([]byte) {
		close(in)
		<-release
	})
	qc.in <- EncodeData(nil, testVNI, []byte("held"))
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
