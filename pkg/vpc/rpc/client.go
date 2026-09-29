// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/wirepb"
)

// Caller starts calls. *Conn is a Caller.
type Caller interface {
	// Invoke makes a unary call.
	Invoke(ctx context.Context, method string, in, out proto.Message) error
	// NewStream starts a streaming call.
	NewStream(ctx context.Context, method string) (*ClientStream, error)
}

// Invoke makes a unary call: it sends in and reads the response into out.
func (c *Conn) Invoke(ctx context.Context, method string, in, out proto.Message) error {
	cs, err := c.newStream(ctx, method, in)
	if err != nil {
		return err
	}
	return cs.recvLast(out)
}

// NewStream starts a streaming call. The call ends when RecvMsg returns an
// error or when ctx ends. The caller must make sure that one of the two occurs.
func (c *Conn) NewStream(ctx context.Context, method string) (*ClientStream, error) {
	return c.newStream(ctx, method, nil)
}

// ClientStream is the calling side of one call. One goroutine can call
// SendMsg and CloseSend while another calls RecvMsg.
type ClientStream struct {
	ctx        context.Context
	conn       *Conn
	str        quic.Stream
	fr         frameReader
	stop       func() bool
	sendClosed atomic.Bool
	done       atomic.Bool
	final      error // Set before done; read only by RecvMsg.
}

// newStream opens a call stream. If first is not nil, it sends first and
// closes the send direction.
func (c *Conn) newStream(ctx context.Context, method string, first proto.Message) (*ClientStream, error) {
	if ctx.Err() != nil {
		return nil, ctxError(ctx)
	}
	h := &wirepb.CallHeader{Method: method}
	if d, ok := ctx.Deadline(); ok {
		t := time.Until(d)
		if t <= 0 {
			return nil, &Error{Code: DeadlineExceeded, Message: "deadline exceeded", cause: context.DeadlineExceeded}
		}
		h.TimeoutNs = int64(t)
	}
	if md, ok := ctx.Value(outgoingMDKey{}).(MD); ok {
		h.Metadata = md
	}
	buf := getBuf()
	defer putBuf(buf)
	b, err := appendCallStart(*buf, h, c.opts.maxHeaderSize)
	if err == nil && first != nil {
		b, err = appendFrame(b, frameMessage, first, c.opts.maxMessageSize)
	}
	*buf = b
	if err != nil {
		return nil, err
	}

	str, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctxError(ctx)
		}
		return nil, transportError(err)
	}
	cs := &ClientStream{ctx: ctx, conn: c, str: str}
	cs.fr.init(str)
	if ctx.Done() != nil {
		cs.stop = context.AfterFunc(ctx, cs.cancel)
	}
	if _, err := str.Write(b); err != nil {
		if err := cs.sendError(err); err != io.EOF {
			return nil, cs.end(err, StreamCanceled)
		}
	}
	if first != nil {
		_ = cs.CloseSend()
	}
	return cs, nil
}

// cancel resets both directions when the call context ends.
func (cs *ClientStream) cancel() {
	code := ctxStreamCode(cs.ctx)
	cs.str.CancelWrite(code)
	cs.str.CancelRead(code)
}

// SendMsg sends m. It returns io.EOF if the called side ended the call;
// RecvMsg then returns the status.
func (cs *ClientStream) SendMsg(m proto.Message) error {
	buf := getBuf()
	b, err := appendFrame(*buf, frameMessage, m, cs.conn.opts.maxMessageSize)
	if err == nil {
		if _, werr := cs.str.Write(b); werr != nil {
			err = cs.sendError(werr)
		}
	}
	*buf = b
	putBuf(buf)
	return err
}

// CloseSend tells the called side that the caller sends no more messages.
func (cs *ClientStream) CloseSend() error {
	if cs.sendClosed.CompareAndSwap(false, true) {
		_ = cs.str.Close()
	}
	return nil
}

func (cs *ClientStream) sendError(err error) error {
	var se *quic.StreamError
	if cs.done.Load() || (errors.As(err, &se) && se.Remote) {
		return io.EOF
	}
	if cs.ctx.Err() != nil {
		return ctxError(cs.ctx)
	}
	return transportError(err)
}

// RecvMsg reads the next message into m. It returns io.EOF after the last
// message when the status is OK, or the status error.
func (cs *ClientStream) RecvMsg(m proto.Message) error {
	if cs.done.Load() {
		return cs.final
	}
	kind, p, err := cs.fr.readFrame(cs.conn.opts.maxMessageSize)
	switch {
	case err != nil:
		if err == io.EOF {
			err = errNoStatus
		}
		return cs.fail(err)
	case kind == frameMessage && m != nil:
		if err := proto.Unmarshal(p, m); err != nil {
			return cs.end(Errorf(Internal, "decode response message: %w", err), StreamProtocolError)
		}
		return nil
	case kind == frameStatus:
		if cs.fr.s != cs.fr.e {
			return cs.fail(errUnexpected) // Data after the status.
		}
		st := decodeStatus(p)
		if st == nil {
			return cs.end(io.EOF, StreamNoError)
		}
		if _, ok := st.(*frameError); ok {
			return cs.fail(st)
		}
		return cs.end(st, StreamNoError)
	}
	return cs.fail(errUnexpected)
}

// recvLast reads the one response message and then the status.
func (cs *ClientStream) recvLast(out proto.Message) error {
	if err := cs.RecvMsg(out); err != nil {
		if err == io.EOF {
			return &Error{Code: Internal, Message: "missing response message"}
		}
		return err
	}
	if err := cs.RecvMsg(nil); err != io.EOF {
		return err
	}
	return nil
}

func (cs *ClientStream) fail(err error) error {
	if cs.ctx.Err() != nil {
		return cs.end(ctxError(cs.ctx), ctxStreamCode(cs.ctx))
	}
	code := StreamCanceled
	if errors.As(err, new(*frameError)) {
		code = StreamProtocolError
	}
	return cs.end(transportError(err), code)
}

// end ends the call with err and releases the stream. Only the RecvMsg
// goroutine calls it.
func (cs *ClientStream) end(err error, code quic.StreamErrorCode) error {
	if cs.stop != nil {
		cs.stop()
	}
	if !cs.fr.atEOF() {
		cs.str.CancelRead(code)
	}
	cs.final = err
	cs.done.Store(true)
	if cs.sendClosed.CompareAndSwap(false, true) {
		cs.str.CancelWrite(code)
	}
	cs.fr.release()
	return err
}
