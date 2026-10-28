// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// readsConn is a DatagramConn that returns its reads in order, then err. With a nil err it
// waits for the context after the reads.
type readsConn struct {
	reads [][][]byte
	err   error
}

func (c *readsConn) ReceiveDatagrams(ctx context.Context, bufs [][]byte) (int, error) {
	if len(c.reads) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	n := copy(bufs, c.reads[0])
	c.reads = c.reads[1:]
	return n, nil
}

func (*readsConn) TrySendDatagram([]byte) error { return nil }

// outTarget is a Target that keeps a copy of each PacketOut and fails the call number fail.
type outTarget struct {
	dp.Target
	got  []*p4.PacketOut
	fail int
}

var errOut = errors.New("packet out failed")

func (o *outTarget) PacketOut(p *p4.PacketOut) error {
	o.got = append(o.got, &p4.PacketOut{Payload: bytes.Clone(p.Payload), Metadata: p.Metadata})
	if len(o.got) == o.fail {
		return errOut
	}
	return nil
}

// TestReadDatagrams gives the reads of a connection of A to the datagram reader. Each datagram
// goes to PacketOut as DATAGRAM in, in order, until the connection ends or PacketOut fails.
func TestReadDatagrams(t *testing.T) {
	const port, session = 7, 9
	datagrams := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	cases := []struct {
		name    string
		reads   [][][]byte
		connErr error
		fail    int
		cancel  bool
		want    int // The PacketOut calls.
		wantErr error
	}{
		{name: "batch of 3", reads: [][][]byte{datagrams}, connErr: io.EOF, want: 3, wantErr: io.EOF},
		{name: "two reads", reads: [][][]byte{datagrams[:1], datagrams[1:]}, connErr: io.EOF, want: 3, wantErr: io.EOF},
		{name: "PacketOut fails on the 2nd", reads: [][][]byte{datagrams}, connErr: io.EOF, fail: 2, want: 2, wantErr: errOut},
		{name: "conn error", connErr: io.EOF, wantErr: io.EOF},
		{name: "ctx done", reads: [][][]byte{datagrams}, cancel: true, want: 3, wantErr: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			tgt := &outTarget{fail: tc.fail}
			err := dp.ReadDatagrams(ctx, tgt, &readsConn{reads: tc.reads, err: tc.connErr}, port, session)
			require.ErrorIs(t, err, tc.wantErr)
			require.Len(t, tgt.got, tc.want)
			for i, po := range tgt.got {
				assert.Equal(t, datagrams[i], po.Payload, "PacketOut %d", i)
				md, err := dp.DecodePacketOutMeta(po.Metadata)
				require.NoError(t, err)
				assert.Equal(t, dp.PacketOutMeta{Kind: dp.KindDatagram, Port: port, Session: session}, md)
			}
		})
	}
}
