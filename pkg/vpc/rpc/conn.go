// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
)

// Conn makes and serves calls on one QUIC connection. Both ends of the
// connection can use a Conn at the same time: each side can call the other.
type Conn struct {
	qc   quic.Connection
	mux  *Mux
	opts options
}

type options struct {
	maxHeaderSize  int
	maxMessageSize int
	headerTimeout  time.Duration
}

// Option sets a Conn option.
type Option func(*options)

// WithMaxHeaderSize sets the maximum size of a call header and of a status message.
func WithMaxHeaderSize(n int) Option { return func(o *options) { o.maxHeaderSize = n } }

// WithMaxMessageSize sets the maximum size of one message in each direction.
func WithMaxMessageSize(n int) Option { return func(o *options) { o.maxMessageSize = n } }

// WithHeaderTimeout sets the time that a peer has to send the call header on a new stream.
func WithHeaderTimeout(d time.Duration) Option { return func(o *options) { o.headerTimeout = d } }

// NewConn returns a Conn on qc. The Conn serves calls with the handlers in mux
// (mux can be nil). The caller owns qc and closes it.
func NewConn(qc quic.Connection, mux *Mux, opts ...Option) *Conn {
	c := &Conn{
		qc:  qc,
		mux: mux,
		opts: options{
			maxHeaderSize:  defaultMaxHeaderSize,
			maxMessageSize: defaultMaxMessageSize,
			headerTimeout:  10 * time.Second,
		},
	}
	for _, o := range opts {
		o(&c.opts)
	}
	return c
}

// QUIC returns the QUIC connection.
func (c *Conn) QUIC() quic.Connection { return c.qc }

type connKey struct{}

// ConnFromContext returns the Conn that serves the call of a handler context.
// A handler can use it to find the peer identity or to call the peer.
func ConnFromContext(ctx context.Context) *Conn {
	c, _ := ctx.Value(connKey{}).(*Conn)
	return c
}

// Serve accepts calls from the peer and runs their handlers, one goroutine
// for each call. It returns when ctx ends or the connection closes, after
// all handlers return.
func (c *Conn) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(context.WithValue(ctx, connKey{}, c))
	stop := context.AfterFunc(c.qc.Context(), func() { cancel(context.Cause(c.qc.Context())) })
	var wg sync.WaitGroup
	var err error
	for {
		var str quic.Stream
		if str, err = c.qc.AcceptStream(ctx); err != nil {
			break
		}
		wg.Go(func() { c.serveStream(ctx, str) })
	}
	stop()
	cancel(err)
	wg.Wait()
	return err
}

// HandlerFunc runs one call. The returned error becomes the call status.
type HandlerFunc func(ctx context.Context, s *ServerStream) error

// Mux maps full method names to handlers. Add all handlers before Serve.
type Mux struct {
	handlers map[string]HandlerFunc
}

// NewMux returns an empty Mux.
func NewMux() *Mux { return &Mux{handlers: map[string]HandlerFunc{}} }

// Handle adds h for method. It panics if method already has a handler.
func (m *Mux) Handle(method string, h HandlerFunc) {
	if _, ok := m.handlers[method]; ok {
		panic("rpc: second handler for " + method)
	}
	m.handlers[method] = h
}

// ServerStream is the called side of one call. One goroutine can call
// RecvMsg while another calls SendMsg.
type ServerStream struct {
	ctx      context.Context
	conn     *Conn
	str      quic.Stream
	fr       frameReader
	method   string
	readCode quic.StreamErrorCode
	json     *jsonCall // Set for a call from JSONHandler.
}

// Method returns the full method name of the call.
func (s *ServerStream) Method() string { return s.method }

// RecvMsg reads the next message into m. It returns io.EOF when the caller
// stops sending.
func (s *ServerStream) RecvMsg(m proto.Message) error {
	if s.json != nil {
		return s.json.recv(m)
	}
	kind, p, err := s.fr.readFrame(s.conn.opts.maxMessageSize, s.conn.opts.maxHeaderSize)
	if err == nil && kind != frameMessage {
		err, s.fr.bad = errUnexpected, errUnexpected
	}
	if err != nil {
		if err == io.EOF {
			return io.EOF
		}
		if s.ctx.Err() != nil {
			return ctxError(s.ctx)
		}
		if errors.As(err, new(*frameError)) {
			s.readCode = StreamProtocolError
		}
		return transportError(err)
	}
	if err := proto.Unmarshal(p, m); err != nil {
		return Errorf(Internal, "decode request message: %w", err)
	}
	return nil
}

// SendMsg sends m to the caller.
func (s *ServerStream) SendMsg(m proto.Message) error {
	if s.json != nil {
		return s.json.send(m)
	}
	buf := getBuf()
	b, err := appendFrame(*buf, frameMessage, m, s.conn.opts.maxMessageSize)
	if err == nil {
		if _, werr := s.str.Write(b); werr != nil {
			err = transportError(werr)
			if s.ctx.Err() != nil {
				err = ctxError(s.ctx)
			}
		}
	}
	*buf = b
	putBuf(buf)
	return err
}

func (c *Conn) serveStream(ctx context.Context, str quic.Stream) {
	s := &ServerStream{ctx: ctx, conn: c, str: str, readCode: StreamNoError}
	s.fr.init(str)
	defer s.fr.release()

	_ = str.SetReadDeadline(time.Now().Add(c.opts.headerTimeout))
	h, err := readCallStart(&s.fr, c.opts.maxHeaderSize)
	if err != nil {
		var fe *frameError
		if errors.As(err, &fe) && fe.unsupported {
			s.abort(StreamUnsupported)
		} else {
			s.abort(StreamProtocolError)
		}
		return
	}
	_ = str.SetReadDeadline(time.Time{})
	s.method = h.Method

	var handler HandlerFunc
	if c.mux != nil {
		handler = c.mux.handlers[h.Method]
	}
	if handler == nil {
		s.finish(ctx, Errorf(Unimplemented, "unknown method %s", h.Method))
		return
	}

	hctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if h.TimeoutNs > 0 {
		var cancelDeadline context.CancelFunc
		hctx, cancelDeadline = context.WithDeadline(hctx, time.Now().Add(time.Duration(h.TimeoutNs)))
		defer cancelDeadline()
	}
	if len(h.Metadata) > 0 {
		hctx = context.WithValue(hctx, incomingMDKey{}, MD(h.Metadata))
	}
	s.ctx = hctx
	// A STOP_SENDING from the caller cancels the send side context and so
	// the handler context. When the handler context ends, reset the stream
	// so that RecvMsg, SendMsg and the status write do not block.
	stopPeer := context.AfterFunc(str.Context(), func() { cancel(context.Cause(str.Context())) })
	stopAbort := context.AfterFunc(hctx, func() { s.abort(ctxStreamCode(hctx)) })
	err = handler(hctx, s)
	// Stop stopPeer first: the Close in finish cancels str.Context(). A
	// STOP_SENDING from the caller still ends a blocked status write.
	stopPeer()
	s.finish(hctx, err)
	stopAbort()
}

// finish sends the status for err and ends both directions of the stream.
func (s *ServerStream) finish(ctx context.Context, err error) {
	if ctx.Err() != nil {
		// The call was canceled or its deadline expired: the stream was reset.
		s.abort(ctxStreamCode(ctx))
		return
	}
	buf := getBuf()
	*buf = appendStatus(*buf, err, s.conn.opts.maxHeaderSize)
	_, werr := s.str.Write(*buf)
	putBuf(buf)
	if werr != nil {
		s.abort(StreamCanceled)
		return
	}
	_ = s.str.Close()
	if !s.fr.atEOF() {
		s.str.CancelRead(s.readCode)
	}
}

func (s *ServerStream) abort(code quic.StreamErrorCode) {
	s.str.CancelWrite(code)
	s.str.CancelRead(code)
}

// MD is call metadata.
type MD map[string]string

type (
	incomingMDKey struct{}
	outgoingMDKey struct{}
)

// NewOutgoingContext returns a context whose calls send md.
func NewOutgoingContext(ctx context.Context, md MD) context.Context {
	return context.WithValue(ctx, outgoingMDKey{}, md)
}

// IncomingMetadata returns the metadata of the call that a handler serves.
func IncomingMetadata(ctx context.Context) MD {
	md, _ := ctx.Value(incomingMDKey{}).(MD)
	return md
}
