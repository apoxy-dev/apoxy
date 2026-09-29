// SPDX-License-Identifier: AGPL-3.0-only

package rpc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/testpb"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/wirepb"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	// In test binaries quic-go parses this variable for each packet. Set it to
	// the default value (100k packets) so that the parse does not allocate.
	_ = os.Setenv("QUIC_GO_TEST_KEY_UPDATE_INTERVAL", "100000")
	os.Exit(m.Run())
}

// testTLS returns mTLS configs with certificates from one test CA.
func testTLS(t testing.TB) (server, client *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	leaf := func(serial int64, cn string, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	server = &tls.Config{
		Certificates: []tls.Certificate{leaf(2, "listener", x509.ExtKeyUsageServerAuth)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		NextProtos:   []string{"apoxy-rpc-test"},
	}
	client = &tls.Config{
		Certificates: []tls.Certificate{leaf(3, "dialer", x509.ExtKeyUsageClientAuth)},
		RootCAs:      pool,
		ServerName:   "localhost",
		NextProtos:   []string{"apoxy-rpc-test"},
	}
	return server, client
}

type pairConfig struct {
	quic             *quic.Config
	opts             []rpc.Option
	noListenerServer bool // The test reads the listener's streams itself.
}

// pair is one QUIC connection with an rpc.Conn on each end.
type pair struct {
	dialer, listener         *rpc.Conn
	dq, lq                   quic.Connection
	dialerSrv, listenerSrv   *echoServer
	stopListener             context.CancelFunc
	listenerServeDone        chan error
	dialerCancel, lCancelAll context.CancelFunc
}

func newPair(t testing.TB, cfg pairConfig) *pair {
	t.Helper()
	serverTLS, clientTLS := testTLS(t)
	qconf := cfg.quic
	if qconf == nil {
		qconf = &quic.Config{}
	}
	qconf.MaxIdleTimeout = 30 * time.Second
	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, qconf)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan quic.Connection, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			c = nil
		}
		accepted <- c
	}()
	dq, err := quic.DialAddr(ctx, ln.Addr().String(), clientTLS, qconf)
	require.NoError(t, err)
	lq := <-accepted
	require.NotNil(t, lq)

	p := &pair{dq: dq, lq: lq, dialerSrv: &echoServer{name: "dialer"}, listenerSrv: &echoServer{name: "listener"}}
	mux := func(srv testpb.EchoServer) *rpc.Mux {
		m := rpc.NewMux()
		testpb.RegisterEchoServer(m, srv)
		return m
	}
	p.dialer = rpc.NewConn(dq, mux(p.dialerSrv), cfg.opts...)
	p.listener = rpc.NewConn(lq, mux(p.listenerSrv), cfg.opts...)

	dctx, dcancel := context.WithCancel(context.Background())
	lctx, lcancel := context.WithCancel(context.Background())
	p.stopListener = lcancel
	p.listenerServeDone = make(chan error, 1)
	dialerDone := make(chan error, 1)
	go func() { dialerDone <- p.dialer.Serve(dctx) }()
	if cfg.noListenerServer {
		p.listenerServeDone <- nil
	} else {
		go func() { p.listenerServeDone <- p.listener.Serve(lctx) }()
	}
	t.Cleanup(func() {
		dcancel()
		lcancel()
		_ = dq.CloseWithError(0, "")
		_ = lq.CloseWithError(0, "")
		<-dialerDone
		<-p.listenerServeDone
		_ = ln.Close()
	})
	return p
}

// callers returns the two call directions of p.
func (p *pair) callers() []struct {
	name   string
	caller *rpc.Conn
	callee *echoServer
} {
	return []struct {
		name   string
		caller *rpc.Conn
		callee *echoServer
	}{
		{"dialer calls listener", p.dialer, p.listenerSrv},
		{"listener calls dialer", p.listener, p.dialerSrv},
	}
}

type handlerReport struct {
	ctxErr   error
	cause    error
	recvErr  error
	deadline time.Time
}

// echoServer implements Echo. Request texts select test behavior. A text
// that starts with "block" makes the handler wait for its context to end.
type echoServer struct {
	name    string
	waiters sync.Map // Request text to *waiter.
	nextKey atomic.Int64
}

type waiter struct {
	started chan struct{}
	report  chan handlerReport
}

// expect returns a unique "block" request text and the channels that its
// handler uses.
func (s *echoServer) expect() (string, *waiter) {
	key := fmt.Sprintf("block %d", s.nextKey.Add(1))
	w := &waiter{started: make(chan struct{}, 1), report: make(chan handlerReport, 1)}
	s.waiters.Store(key, w)
	return key, w
}

// block runs the "block" behavior: signal the start, wait for the context,
// and report.
func (s *echoServer) block(ctx context.Context, key string, recv func() error) error {
	v, _ := s.waiters.LoadAndDelete(key)
	w, _ := v.(*waiter)
	if w != nil {
		w.started <- struct{}{}
	}
	var recvErr error
	if recv != nil {
		recvErr = recv()
	}
	<-ctx.Done()
	if w != nil {
		d, _ := ctx.Deadline()
		w.report <- handlerReport{ctxErr: ctx.Err(), cause: context.Cause(ctx), recvErr: recvErr, deadline: d}
	}
	return ctx.Err()
}

func (s *echoServer) Unary(ctx context.Context, in *testpb.EchoRequest) (*testpb.EchoResponse, error) {
	out := &testpb.EchoResponse{Text: in.Text, ServedBy: s.name, Payload: in.Payload}
	switch {
	case in.Text == "deadline":
		if d, ok := ctx.Deadline(); ok {
			out.Payload = binary.BigEndian.AppendUint64(nil, uint64(d.UnixNano()))
		}
	case strings.HasPrefix(in.Text, "block"):
		return nil, s.block(ctx, in.Text, nil)
	case in.Text == "plain error":
		return nil, errors.New("plain error")
	case strings.HasPrefix(in.Text, "code "):
		var c uint32
		_, _ = fmt.Sscanf(in.Text, "code %d", &c)
		return nil, rpc.Errorf(rpc.Code(c), "handler error")
	case in.Text == "metadata":
		conn := rpc.ConnFromContext(ctx)
		if conn == nil {
			return nil, rpc.Errorf(rpc.Internal, "no conn")
		}
		certs := conn.QUIC().ConnectionState().TLS.PeerCertificates
		out.Text = rpc.IncomingMetadata(ctx)["k"] + " " + certs[0].Subject.CommonName
	}
	return out, nil
}

func (s *echoServer) ServerStream(ctx context.Context, in *testpb.EchoRequest, st rpc.ServerStreamServer[testpb.EchoResponse]) error {
	for i := range in.Count {
		if err := st.Send(&testpb.EchoResponse{Text: in.Text, ServedBy: s.name, Seq: i, Payload: in.Payload}); err != nil {
			return err
		}
	}
	return nil
}

func (s *echoServer) ClientStream(ctx context.Context, st rpc.ClientStreamServer[testpb.EchoRequest]) (*testpb.EchoResponse, error) {
	var texts []string
	for {
		in, err := st.Recv()
		if err == io.EOF {
			return &testpb.EchoResponse{Text: strings.Join(texts, ","), ServedBy: s.name}, nil
		}
		if err != nil {
			return nil, err
		}
		texts = append(texts, in.Text)
	}
}

func (s *echoServer) Bidi(ctx context.Context, st rpc.BidiStreamServer[testpb.EchoRequest, testpb.EchoResponse]) error {
	for seq := uint32(0); ; seq++ {
		in, err := st.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(in.Text, "block"):
			return s.block(ctx, in.Text, func() error { _, err := st.Recv(); return err })
		case in.Text == "stop":
			return nil
		}
		if err := st.Send(&testpb.EchoResponse{Text: in.Text, ServedBy: s.name, Seq: seq, Payload: in.Payload}); err != nil {
			return err
		}
	}
}

func TestCallsBothDirections(t *testing.T) {
	const callsPerSide = 32
	type call func(ctx context.Context, c testpb.EchoClient, text, want string) error
	check := func(out *testpb.EchoResponse, text, want string, seq uint32) error {
		if out.Text != text || out.ServedBy != want || out.Seq != seq {
			return fmt.Errorf("got %v, want text %q from %q seq %d", out, text, want, seq)
		}
		return nil
	}
	cases := []struct {
		name string
		call call
	}{
		{"unary", func(ctx context.Context, c testpb.EchoClient, text, want string) error {
			out, err := c.Unary(ctx, &testpb.EchoRequest{Text: text})
			if err != nil {
				return err
			}
			return check(out, text, want, 0)
		}},
		{"server stream", func(ctx context.Context, c testpb.EchoClient, text, want string) error {
			st, err := c.ServerStream(ctx, &testpb.EchoRequest{Text: text, Count: 5})
			if err != nil {
				return err
			}
			for i := uint32(0); ; i++ {
				out, err := st.Recv()
				if err == io.EOF {
					if i != 5 {
						return fmt.Errorf("got %d messages", i)
					}
					return nil
				}
				if err != nil {
					return err
				}
				if err := check(out, text, want, i); err != nil {
					return err
				}
			}
		}},
		{"client stream", func(ctx context.Context, c testpb.EchoClient, text, want string) error {
			st, err := c.ClientStream(ctx)
			if err != nil {
				return err
			}
			for range 3 {
				if err := st.Send(&testpb.EchoRequest{Text: text}); err != nil {
					return err
				}
			}
			out, err := st.CloseAndRecv()
			if err != nil {
				return err
			}
			return check(out, strings.Join([]string{text, text, text}, ","), want, 0)
		}},
		{"bidi", func(ctx context.Context, c testpb.EchoClient, text, want string) error {
			st, err := c.Bidi(ctx)
			if err != nil {
				return err
			}
			for i := range uint32(4) {
				if err := st.Send(&testpb.EchoRequest{Text: text}); err != nil {
					return err
				}
				out, err := st.Recv()
				if err != nil {
					return err
				}
				if err := check(out, text, want, i); err != nil {
					return err
				}
			}
			if err := st.CloseSend(); err != nil {
				return err
			}
			if _, err := st.Recv(); err != io.EOF {
				return fmt.Errorf("got %v, want io.EOF", err)
			}
			return nil
		}},
	}
	p := newPair(t, pairConfig{})
	// runAll runs callsPerSide calls from each side at the same time; call i uses calls[i%len(calls)].
	runAll := func(t *testing.T, calls ...call) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		errs := make(chan error, 2*callsPerSide)
		for _, side := range p.callers() {
			c := testpb.NewEchoClient(side.caller)
			for i := range callsPerSide {
				wg.Go(func() {
					if err := calls[i%len(calls)](ctx, c, fmt.Sprintf("%s %d", side.name, i), side.callee.name); err != nil {
						errs <- fmt.Errorf("%s: %w", side.name, err)
					}
				})
			}
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	}
	var all []call
	for _, tc := range cases {
		all = append(all, tc.call)
		t.Run(tc.name, func(t *testing.T) { runAll(t, tc.call) })
	}
	t.Run("all kinds at once", func(t *testing.T) { runAll(t, all...) })
}

// requireStreamError checks that err holds a QUIC stream error from the peer with code.
func requireStreamError(t *testing.T, err error, code quic.StreamErrorCode) {
	t.Helper()
	var se *quic.StreamError
	require.ErrorAs(t, err, &se)
	assert.True(t, se.Remote, "stream error is not from the peer: %v", se)
	assert.Equal(t, code, se.ErrorCode)
}

func TestCancelEndsHandler(t *testing.T) {
	p := newPair(t, pairConfig{})
	cases := []struct {
		name     string
		timeout  time.Duration
		wantCode rpc.Code
	}{
		{"cancel", 0, rpc.Canceled},
		{"deadline", 100 * time.Millisecond, rpc.DeadlineExceeded},
	}
	for _, tc := range cases {
		for _, side := range p.callers() {
			t.Run(tc.name+"/"+side.name, func(t *testing.T) {
				key, w := side.callee.expect()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if tc.timeout > 0 {
					ctx, cancel = context.WithTimeout(ctx, tc.timeout)
					defer cancel()
				}
				st, err := testpb.NewEchoClient(side.caller).Bidi(ctx)
				require.NoError(t, err)
				require.NoError(t, st.Send(&testpb.EchoRequest{Text: key}))
				<-w.started
				if tc.timeout == 0 {
					cancel()
				}
				_, err = st.Recv()
				assert.Equal(t, tc.wantCode, rpc.CodeOf(err), "client error: %v", err)

				r := <-w.report
				require.Error(t, r.ctxErr)
				if tc.timeout == 0 {
					// STOP_SENDING and RESET_STREAM from the caller carry StreamCanceled.
					requireStreamError(t, r.cause, rpc.StreamCanceled)
					requireStreamError(t, r.recvErr, rpc.StreamCanceled)
					assert.Equal(t, rpc.Canceled, rpc.CodeOf(r.recvErr))
				} else {
					d, _ := ctx.Deadline()
					assert.WithinDuration(t, d, r.deadline, 250*time.Millisecond)
				}
			})
		}
	}
}

// rawCallStart returns the stream preamble and a call header frame.
func rawCallStart(method string, timeout time.Duration) []byte {
	h, _ := proto.Marshal(&wirepb.CallHeader{Method: method, TimeoutNs: int64(timeout)})
	return append(protowire.AppendVarint([]byte{0x01, 0x01, 0x01}, uint64(len(h))), h...)
}

func rawFrame(kind byte, m proto.Message) []byte {
	b, _ := proto.Marshal(m)
	return append(protowire.AppendVarint([]byte{kind}, uint64(len(b))), b...)
}

// readRawStatus reads frames until the status frame and returns it.
func readRawStatus(t *testing.T, r io.Reader) *wirepb.Status {
	t.Helper()
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	for len(b) > 0 {
		kind := b[0]
		n, l := protowire.ConsumeVarint(b[1:])
		require.Positive(t, l)
		p := b[1+l : 1+l+int(n)]
		b = b[1+l+int(n):]
		if kind == 0x03 {
			st := &wirepb.Status{}
			require.NoError(t, proto.Unmarshal(p, st))
			require.Empty(t, b, "data after the status")
			return st
		}
	}
	t.Fatal("no status frame")
	return nil
}

// writeUntilError writes to str until the peer's STOP_SENDING makes Write fail.
func writeUntilError(str quic.SendStream) error {
	buf := make([]byte, 1024)
	for range 100000 {
		if _, err := str.Write(rawFrame(0x02, &wirepb.Status{Message: string(buf)})); err != nil {
			return err
		}
	}
	return errors.New("write did not fail")
}

func TestCallerResetCodes(t *testing.T) {
	cases := []struct {
		name     string
		timeout  time.Duration
		wantCode quic.StreamErrorCode
	}{
		{"cancel", 0, rpc.StreamCanceled},
		{"deadline", 50 * time.Millisecond, rpc.StreamDeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPair(t, pairConfig{noListenerServer: true})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				defer cancel()
			}
			callErr := make(chan error, 1)
			go func() {
				// The send direction stays open, so the peer sees RESET_STREAM.
				cs, err := p.dialer.NewStream(ctx, testpb.Echo_Bidi_FullMethodName)
				if err == nil {
					err = cs.RecvMsg(&testpb.EchoResponse{})
				}
				callErr <- err
			}()
			actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer acancel()
			str, err := p.lq.AcceptStream(actx)
			require.NoError(t, err)
			if tc.timeout == 0 {
				cancel()
			}
			// RESET_STREAM: Read fails after the header.
			_, err = io.ReadAll(str)
			requireStreamError(t, err, tc.wantCode)
			// STOP_SENDING: Write fails.
			requireStreamError(t, writeUntilError(str), tc.wantCode)
			requireStreamError(t, context.Cause(str.Context()), tc.wantCode)

			if tc.timeout > 0 {
				assert.Equal(t, rpc.DeadlineExceeded, rpc.CodeOf(<-callErr))
			} else {
				assert.Equal(t, rpc.Canceled, rpc.CodeOf(<-callErr))
			}
		})
	}
}

func TestCalledSideResets(t *testing.T) {
	// Rows with wantReset keep the send direction open to see STOP_SENDING.
	cases := []struct {
		name       string
		data       []byte
		wantReset  quic.StreamErrorCode
		wantStatus rpc.Code // Used when wantReset is 0.
		closeSend  bool
	}{
		{"unknown type", []byte{0x02, 0x01}, rpc.StreamUnsupported, 0, false},
		{"unknown version", []byte{0x01, 0x02}, rpc.StreamUnsupported, 0, false},
		{"header not valid", []byte{0x01, 0x01, 0x01, 0x02, 0xff, 0xff}, rpc.StreamProtocolError, 0, false},
		{"header too large", append([]byte{0x01, 0x01, 0x01}, protowire.AppendVarint(nil, 1<<20)...), rpc.StreamProtocolError, 0, false},
		{"header timeout", []byte{0x01}, rpc.StreamProtocolError, 0, false},
		{"handler deadline", rawCallStart(testpb.Echo_Bidi_FullMethodName, 50*time.Millisecond), rpc.StreamDeadlineExceeded, 0, false},
		{"unknown method", rawCallStart("/x.Y/Z", 0), 0, rpc.Unimplemented, true},
		{"missing request", rawCallStart(testpb.Echo_Unary_FullMethodName, 0), 0, rpc.InvalidArgument, true},
		{"message too large", append(rawCallStart(testpb.Echo_Bidi_FullMethodName, 0), append([]byte{0x02}, protowire.AppendVarint(nil, 5<<20)...)...), 0, rpc.ResourceExhausted, false},
		{"status from caller", append(rawCallStart(testpb.Echo_Bidi_FullMethodName, 0), rawFrame(0x03, &wirepb.Status{})...), 0, rpc.Internal, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPair(t, pairConfig{opts: []rpc.Option{rpc.WithHeaderTimeout(100 * time.Millisecond)}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			str, err := p.dq.OpenStreamSync(ctx)
			require.NoError(t, err)
			data := tc.data
			if tc.name == "handler deadline" {
				data = append(data, rawFrame(0x02, &testpb.EchoRequest{Text: "block"})...)
			}
			_, err = str.Write(data)
			require.NoError(t, err)
			if tc.closeSend {
				require.NoError(t, str.Close())
			}
			if tc.wantReset != 0 {
				_, err = io.ReadAll(str)
				requireStreamError(t, err, tc.wantReset)
				requireStreamError(t, writeUntilError(str), tc.wantReset)
				return
			}
			st := readRawStatus(t, str)
			assert.Equal(t, tc.wantStatus, rpc.Code(st.Code), "status: %v", st)
		})
	}
}

func TestHandlerEndsEarly(t *testing.T) {
	// The handler returns while the caller still sends: the caller gets
	// STOP_SENDING with StreamNoError, then the OK status.
	p := newPair(t, pairConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := p.dq.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write(append(rawCallStart(testpb.Echo_Bidi_FullMethodName, 0), rawFrame(0x02, &testpb.EchoRequest{Text: "stop"})...))
	require.NoError(t, err)
	st := readRawStatus(t, str)
	assert.Equal(t, uint32(rpc.OK), st.Code)
	requireStreamError(t, writeUntilError(str), rpc.StreamNoError)

	// The same with the typed client: Send returns io.EOF and Recv the status.
	bidi, err := testpb.NewEchoClient(p.dialer).Bidi(ctx)
	require.NoError(t, err)
	require.NoError(t, bidi.Send(&testpb.EchoRequest{Text: "stop"}))
	for err == nil {
		err = bidi.Send(&testpb.EchoRequest{Text: strings.Repeat("x", 1000)})
	}
	assert.Equal(t, io.EOF, err)
	_, err = bidi.Recv()
	assert.Equal(t, io.EOF, err)
}

func TestHandlerErrors(t *testing.T) {
	p := newPair(t, pairConfig{})
	cases := []struct {
		name string
		text string
		want rpc.Code
	}{
		{"ok", "hello", rpc.OK},
		{"not found", fmt.Sprintf("code %d", rpc.NotFound), rpc.NotFound},
		{"permission denied", fmt.Sprintf("code %d", rpc.PermissionDenied), rpc.PermissionDenied},
		{"code not known", "code 99", rpc.Code(99)},
		{"plain error", "plain error", rpc.Unknown},
	}
	for _, tc := range cases {
		for _, side := range p.callers() {
			t.Run(tc.name+"/"+side.name, func(t *testing.T) {
				_, err := testpb.NewEchoClient(side.caller).Unary(context.Background(), &testpb.EchoRequest{Text: tc.text})
				assert.Equal(t, tc.want, rpc.CodeOf(err), "error: %v", err)
			})
		}
	}
}

func TestShutdown(t *testing.T) {
	cases := []struct {
		name string
		stop func(p *pair)
		want rpc.Code
	}{
		{"serve context canceled", func(p *pair) { p.stopListener() }, rpc.Canceled},
		{"connection closed", func(p *pair) { _ = p.lq.CloseWithError(0x42, "bye") }, rpc.Unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPair(t, pairConfig{})
			key, w := p.listenerSrv.expect()
			errc := make(chan error, 1)
			go func() {
				_, err := testpb.NewEchoClient(p.dialer).Unary(context.Background(), &testpb.EchoRequest{Text: key})
				errc <- err
			}()
			<-w.started
			tc.stop(p)
			err := <-errc
			assert.Equal(t, tc.want, rpc.CodeOf(err), "error: %v", err)
			select {
			case <-p.listenerServeDone:
				p.listenerServeDone <- nil
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return")
			}
		})
	}
}

func TestDeadlines(t *testing.T) {
	p := newPair(t, pairConfig{})
	c := testpb.NewEchoClient(p.dialer)
	cases := []struct {
		name     string
		timeout  time.Duration // Negative means expired before the call.
		text     string
		want     rpc.Code
		deadline bool
	}{
		{"no deadline", 0, "deadline", rpc.OK, false},
		{"deadline sent", 5 * time.Second, "deadline", rpc.OK, true},
		{"expired before the call", -time.Second, "deadline", rpc.DeadlineExceeded, false},
		{"expires during the call", 50 * time.Millisecond, "block", rpc.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.timeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				defer cancel()
			}
			start := time.Now()
			out, err := c.Unary(ctx, &testpb.EchoRequest{Text: tc.text})
			require.Equal(t, tc.want, rpc.CodeOf(err), "error: %v", err)
			if tc.want == rpc.DeadlineExceeded {
				assert.Less(t, time.Since(start), time.Second)
				return
			}
			if !tc.deadline {
				assert.Empty(t, out.Payload)
				return
			}
			want, _ := ctx.Deadline()
			got := time.Unix(0, int64(binary.BigEndian.Uint64(out.Payload)))
			assert.WithinDuration(t, want, got, 250*time.Millisecond)
		})
	}
}

func TestMetadataAndPeer(t *testing.T) {
	p := newPair(t, pairConfig{})
	ctx := rpc.NewOutgoingContext(context.Background(), rpc.MD{"k": "v"})
	out, err := testpb.NewEchoClient(p.dialer).Unary(ctx, &testpb.EchoRequest{Text: "metadata"})
	require.NoError(t, err)
	assert.Equal(t, "v dialer", out.Text)
	out, err = testpb.NewEchoClient(p.listener).Unary(ctx, &testpb.EchoRequest{Text: "metadata"})
	require.NoError(t, err)
	assert.Equal(t, "v listener", out.Text)
}

func TestMessageLimits(t *testing.T) {
	p := newPair(t, pairConfig{opts: []rpc.Option{rpc.WithMaxMessageSize(1 << 10)}})
	c := testpb.NewEchoClient(p.dialer)
	cases := []struct {
		name string
		call func() error
	}{
		{"unary request", func() error {
			_, err := c.Unary(context.Background(), &testpb.EchoRequest{Payload: make([]byte, 2<<10)})
			return err
		}},
		{"stream request", func() error {
			st, err := c.Bidi(context.Background())
			require.NoError(t, err)
			defer func() { _ = st.CloseSend(); _, _ = st.Recv() }()
			return st.Send(&testpb.EchoRequest{Payload: make([]byte, 2<<10)})
		}},
		{"response", func() error {
			// 600 B request, 5 responses; the Seq field makes each response a bit larger.
			st, err := c.ServerStream(context.Background(), &testpb.EchoRequest{Payload: make([]byte, 1<<10-8), Count: 5})
			require.NoError(t, err)
			for {
				if _, err := st.Recv(); err != nil {
					return err
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			assert.Equal(t, rpc.ResourceExhausted, rpc.CodeOf(err), "error: %v", err)
		})
	}
}

// TestNoStreamLeaks runs many calls of each kind, with errors and cancels,
// on a connection that allows only two open streams in each direction. A
// stream that does not close blocks the next calls.
func TestNoStreamLeaks(t *testing.T) {
	iterations := 1000
	if testing.Short() {
		iterations = 100
	}
	p := newPair(t, pairConfig{quic: &quic.Config{MaxIncomingStreams: 2}})
	baseline := runtime.NumGoroutine()

	calls := []struct {
		name string
		run  func(ctx context.Context, c testpb.EchoClient, callee *echoServer) error
	}{
		{"unary", func(ctx context.Context, c testpb.EchoClient, _ *echoServer) error {
			_, err := c.Unary(ctx, &testpb.EchoRequest{Text: "x"})
			return err
		}},
		{"unary error", func(ctx context.Context, c testpb.EchoClient, _ *echoServer) error {
			_, err := c.Unary(ctx, &testpb.EchoRequest{Text: "code 5"})
			return expectCode(err, rpc.NotFound)
		}},
		{"server stream", func(ctx context.Context, c testpb.EchoClient, _ *echoServer) error {
			st, err := c.ServerStream(ctx, &testpb.EchoRequest{Text: "x", Count: 3})
			if err != nil {
				return err
			}
			for {
				if _, err := st.Recv(); err != nil {
					return expectEOF(err)
				}
			}
		}},
		{"client stream", func(ctx context.Context, c testpb.EchoClient, _ *echoServer) error {
			st, err := c.ClientStream(ctx)
			if err != nil {
				return err
			}
			if err := st.Send(&testpb.EchoRequest{Text: "x"}); err != nil {
				return err
			}
			_, err = st.CloseAndRecv()
			return err
		}},
		{"bidi", func(ctx context.Context, c testpb.EchoClient, _ *echoServer) error {
			st, err := c.Bidi(ctx)
			if err != nil {
				return err
			}
			if err := st.Send(&testpb.EchoRequest{Text: "x"}); err != nil {
				return err
			}
			if _, err := st.Recv(); err != nil {
				return err
			}
			_ = st.CloseSend()
			_, err = st.Recv()
			return expectEOF(err)
		}},
		{"bidi handler ends early", func(ctx context.Context, c testpb.EchoClient, _ *echoServer) error {
			st, err := c.Bidi(ctx)
			if err != nil {
				return err
			}
			if err := st.Send(&testpb.EchoRequest{Text: "stop"}); err != nil {
				return err
			}
			_, err = st.Recv()
			return expectEOF(err)
		}},
		{"bidi canceled", func(ctx context.Context, c testpb.EchoClient, callee *echoServer) error {
			key, w := callee.expect()
			cctx, cancel := context.WithCancel(ctx)
			defer cancel()
			st, err := c.Bidi(cctx)
			if err != nil {
				return err
			}
			if err := st.Send(&testpb.EchoRequest{Text: key}); err != nil {
				return err
			}
			<-w.started
			cancel()
			_, err = st.Recv()
			<-w.report
			return expectCode(err, rpc.Canceled)
		}},
		{"unary deadline", func(ctx context.Context, c testpb.EchoClient, callee *echoServer) error {
			key, _ := callee.expect()
			dctx, cancel := context.WithTimeout(ctx, time.Millisecond)
			defer cancel()
			_, err := c.Unary(dctx, &testpb.EchoRequest{Text: key})
			return expectCode(err, rpc.DeadlineExceeded)
		}},
		{"unknown method", func(ctx context.Context, _ testpb.EchoClient, _ *echoServer) error {
			return nil // Replaced below; it needs the Conn.
		}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	for i := range iterations {
		for _, side := range p.callers() {
			c := testpb.NewEchoClient(side.caller)
			for _, call := range calls {
				cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
				var err error
				if call.name == "unknown method" {
					err = expectCode(side.caller.Invoke(cctx, "/x.Y/Z", &testpb.EchoRequest{}, &testpb.EchoResponse{}), rpc.Unimplemented)
				} else {
					err = call.run(cctx, c, side.callee)
				}
				ccancel()
				require.NoError(t, err, "iteration %d, %s, %s", i, side.name, call.name)
			}
		}
		// A stream with an unknown version, reset by the called side.
		rawUnsupported(t, p.dq)
	}
	t.Logf("%d calls in %v", iterations*(2*len(calls)+1), time.Since(start))
	for end := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > baseline && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	require.LessOrEqual(t, runtime.NumGoroutine(), baseline, "goroutines after the calls")
}

func rawUnsupported(t *testing.T, qc quic.Connection) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := qc.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write([]byte{0x01, 0x09})
	require.NoError(t, err)
	require.NoError(t, str.Close())
	_, err = io.ReadAll(str)
	requireStreamError(t, err, rpc.StreamUnsupported)
}

func expectCode(err error, want rpc.Code) error {
	if got := rpc.CodeOf(err); got != want {
		return fmt.Errorf("got code %v (%v), want %v", got, err, want)
	}
	return nil
}

func expectEOF(err error) error {
	if err != io.EOF {
		return fmt.Errorf("got %v, want io.EOF", err)
	}
	return nil
}
