// SPDX-License-Identifier: AGPL-3.0-only

package datapathv1_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(m.Run())
}

// connect opens a loopback QUIC connection with alpn and runs an rpc.Conn on
// each end. The dialer serves dialerMux and the listener serves listenerMux.
func connect(t *testing.T, alpn string, dialerMux, listenerMux *rpc.Mux) (dialer, listener *rpc.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{alpn},
	}
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}}

	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		c, _ := ln.Accept(ctx)
		accepted <- c
	}()
	// Dial from 127.0.0.1. On macOS the wildcard socket of DialAddr can get a
	// port that a 127.0.0.1 socket holds, and the replies then go to that socket.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	dq, err := quic.Dial(ctx, udp, ln.Addr(), clientTLS, nil)
	require.NoError(t, err)
	lq := <-accepted
	require.NotNil(t, lq)
	require.Equal(t, alpn, dq.ConnectionState().TLS.NegotiatedProtocol)

	dialer, listener = rpc.NewConn(dq, dialerMux), rpc.NewConn(lq, listenerMux)
	sctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { _ = dialer.Serve(sctx) })
	wg.Go(func() { _ = listener.Serve(sctx) })
	t.Cleanup(func() {
		stop()
		_ = dq.CloseWithError(0, "")
		_ = lq.CloseWithError(0, "")
		wg.Wait()
		_ = ln.Close()
		_ = udp.Close()
	})
	return dialer, listener
}

// stub records the requests of each method and returns the answer of the
// method: a proto.Message or an error.
type stub struct {
	mu      sync.Mutex
	answers map[string]any
	got     map[string][]proto.Message
}

func newStub() *stub { return &stub{answers: map[string]any{}, got: map[string][]proto.Message{}} }

// expect sets the answer of method and clears its requests.
func (s *stub) expect(method string, answer any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[method], s.got[method] = answer, nil
}

func (s *stub) record(method string, in proto.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got[method] = append(s.got[method], in)
}

func (s *stub) requests(method string) []proto.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got[method]
}

func answer[T proto.Message](s *stub, method string, in proto.Message) (T, error) {
	s.record(method, in)
	s.mu.Lock()
	a := s.answers[method]
	s.mu.Unlock()
	var zero T
	switch a := a.(type) {
	case error:
		return zero, a
	case T:
		return a, nil
	}
	return zero, rpc.Errorf(rpc.Internal, "no answer for %s", method)
}

type relayStub struct {
	*stub
	welcome *dp.SessionResponse
	pushes  []*dp.SessionResponse
}

// Session answers Hello with Welcome. Then it sends the pushes while it
// records the messages of the agent.
func (r *relayStub) Session(ctx context.Context, st rpc.BidiStreamServer[dp.SessionRequest, dp.SessionResponse]) error {
	in, err := st.Recv()
	if err != nil {
		return err
	}
	if in.GetHello() == nil {
		return rpc.Errorf(rpc.InvalidArgument, "first message is not Hello")
	}
	r.record("Session", in)
	if err := st.Send(r.welcome); err != nil {
		return err
	}
	pushed := make(chan error, 1)
	go func() {
		for _, p := range r.pushes {
			if err := st.Send(p); err != nil {
				pushed <- err
				return
			}
		}
		pushed <- nil
	}()
	for {
		in, err := st.Recv()
		if err == io.EOF {
			return <-pushed
		}
		if err != nil {
			<-pushed
			return err
		}
		r.record("Session", in)
	}
}

func (r *relayStub) Attach(ctx context.Context, in *dp.AttachRequest) (*dp.AttachResponse, error) {
	return answer[*dp.AttachResponse](r.stub, "Attach", in)
}

func (r *relayStub) Detach(ctx context.Context, in *dp.DetachRequest) (*emptypb.Empty, error) {
	return answer[*emptypb.Empty](r.stub, "Detach", in)
}

func (r *relayStub) Rekey(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	return answer[*dp.KeysResponse](r.stub, "Rekey", in)
}

func (r *relayStub) RegisterLanes(ctx context.Context, in *dp.RegisterLanesRequest) (*emptypb.Empty, error) {
	return answer[*emptypb.Empty](r.stub, "RegisterLanes", in)
}

type peerStub struct{ *stub }

func (p peerStub) Hello(ctx context.Context, in *dp.PeerHello) (*dp.PeerHello, error) {
	return answer[*dp.PeerHello](p.stub, "Hello", in)
}

func (p peerStub) Keys(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	return answer[*dp.KeysResponse](p.stub, "Keys", in)
}

func (p peerStub) Candidates(ctx context.Context, in *dp.Candidates) (*emptypb.Empty, error) {
	return answer[*emptypb.Empty](p.stub, "Candidates", in)
}

type meshStub struct{ *stub }

func (m meshStub) Open(ctx context.Context, in *dp.MeshOpenRequest) (*dp.MeshOpenResponse, error) {
	return answer[*dp.MeshOpenResponse](m.stub, "Open", in)
}

// Presence acks each message.
func (m meshStub) Presence(ctx context.Context, st rpc.BidiStreamServer[dp.PresenceUpdate, dp.PresenceControl]) error {
	for {
		in, err := st.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		m.record("Presence", in)
		if err := st.Send(&dp.PresenceControl{Ack: in.GetSeq()}); err != nil {
			return err
		}
	}
}

func (m meshStub) TrunkKeys(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	return answer[*dp.KeysResponse](m.stub, "TrunkKeys", in)
}

// Snapshot sends its answer as the one part of the stream.
func (m meshStub) Snapshot(ctx context.Context, in *dp.SnapshotRequest, st rpc.ServerStreamServer[dp.SnapshotPart]) error {
	part, err := answer[*dp.SnapshotPart](m.stub, "Snapshot", in)
	if err != nil {
		return err
	}
	return st.Send(part)
}

// Test messages.
var (
	vpc    = &dp.VPCRef{ProjectId: "11111111-2222-3333-4444-555555555555", VpcUid: "vpc-uid-1", NetworkId: 0x0a0b0c}
	relay  = &dp.RelayRef{Id: "relay-b", Addresses: []string{"198.51.100.2:443", "[2001:db8::2]:443"}}
	sa     = &dp.SA{Spi: 0x8000_1234, Key: bytes.Repeat([]byte{7}, 16), Vni: 0x0a0b0c, ExpiresIn: durationpb.New(10 * time.Minute), Lane: 3}
	offer  = &dp.KeysRequest{Op: &dp.KeysRequest_Offer{Offer: &dp.OfferSAs{Sas: []*dp.SA{sa}}}}
	rekey  = &dp.KeysRequest{Op: &dp.KeysRequest_Rekey{Rekey: &dp.RekeySA{Sas: []*dp.SA{sa}}}}
	revoke = &dp.KeysRequest{Op: &dp.KeysRequest_Revoke{Revoke: &dp.RevokeSA{Spis: []uint32{sa.Spi}}}}
)

// call is one call to run. The first word of name is the method. The called
// side must record sent, and the caller must get answer: a proto.Message or
// an error.
type call struct {
	name   string
	do     func(ctx context.Context, c *rpc.Conn) (proto.Message, error)
	sent   []proto.Message
	answer any
}

func unary[C any, Req, Res proto.Message](name string, client func(rpc.Caller) C, f func(C, context.Context, Req) (Res, error), in Req, answer any) call {
	return call{
		name:   name,
		do:     func(ctx context.Context, c *rpc.Conn) (proto.Message, error) { return f(client(c), ctx, in) },
		sent:   []proto.Message{in},
		answer: answer,
	}
}

// bidiStream sends in and reads one answer after each message. It returns the
// last answer.
func bidiStream[C, Req, Res any](name string, client func(rpc.Caller) C, open func(C, context.Context) (rpc.BidiStreamClient[Req, Res], error), answer any, in ...*Req) call {
	tc := call{name: name, answer: answer}
	for _, m := range in {
		tc.sent = append(tc.sent, any(m).(proto.Message))
	}
	tc.do = func(ctx context.Context, c *rpc.Conn) (proto.Message, error) {
		st, err := open(client(c), ctx)
		if err != nil {
			return nil, err
		}
		var last *Res
		for _, m := range in {
			if err := st.Send(m); err != nil {
				return nil, err
			}
			if last, err = st.Recv(); err != nil {
				return nil, err
			}
		}
		if err := st.CloseSend(); err != nil {
			return nil, err
		}
		if _, err := st.Recv(); err != io.EOF {
			return nil, fmt.Errorf("got %v after the end, not EOF", err)
		}
		return any(last).(proto.Message), nil
	}
	return tc
}

// serverStream is a call with one request and a stream of answers. The called
// side sends one message, and then the stream must end.
func serverStream[C any, Req proto.Message, Res any](name string, client func(rpc.Caller) C, open func(C, context.Context, Req) (rpc.ServerStreamClient[Res], error), in Req, answer any) call {
	return call{
		name:   name,
		sent:   []proto.Message{in},
		answer: answer,
		do: func(ctx context.Context, c *rpc.Conn) (proto.Message, error) {
			st, err := open(client(c), ctx, in)
			if err != nil {
				return nil, err
			}
			out, err := st.Recv()
			if err != nil {
				return nil, err
			}
			if _, err := st.Recv(); err != io.EOF {
				return nil, fmt.Errorf("after the last message: %v", err)
			}
			return any(out).(proto.Message), nil
		},
	}
}

func diff(want, got any) string { return cmp.Diff(want, got, protocmp.Transform()) }

func runCalls(t *testing.T, c *rpc.Conn, callee *stub, calls []call) {
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			method := strings.Fields(tc.name)[0]
			callee.expect(method, tc.answer)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := tc.do(ctx, c)
			if want, ok := tc.answer.(*rpc.Error); ok {
				require.Error(t, err)
				assert.Equal(t, want.Code, rpc.CodeOf(err))
				assert.Contains(t, err.Error(), want.Message)
			} else {
				require.NoError(t, err)
				assert.Empty(t, diff(tc.answer, got))
			}
			assert.Empty(t, diff(tc.sent, callee.requests(method)))
		})
	}
}

// runBothWays serves a stub on each end of one connection and runs the calls
// in each direction.
func runBothWays(t *testing.T, alpn string, register func(*rpc.Mux, *stub), calls []call) {
	a, b := newStub(), newStub()
	ma, mb := rpc.NewMux(), rpc.NewMux()
	register(ma, a)
	register(mb, b)
	dialer, listener := connect(t, alpn, ma, mb)
	t.Run("dialer calls listener", func(t *testing.T) { runCalls(t, dialer, b, calls) })
	t.Run("listener calls dialer", func(t *testing.T) { runCalls(t, listener, a, calls) })
}

// TestCheckRevision checks a revision against the minimum of the other side.
func TestCheckRevision(t *testing.T) {
	cases := []struct {
		name  string
		v     *dp.Version
		least uint32
		want  string // Error text. Empty means no error.
	}{
		{name: "equal", v: &dp.Version{Revision: 21}, least: 21},
		{name: "above", v: &dp.Version{Revision: 22}, least: 21},
		{name: "one below", v: &dp.Version{Revision: 20}, least: 21, want: "relay revision 20 is below the minimum 21"},
		{name: "no version against minimum 0", least: 0},
		{name: "no version against minimum 1", least: 1, want: "relay revision 0 is below the minimum 1"},
		{name: "this build against its own minimum", v: dp.LocalVersion("test"), least: dp.MinRevision},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := dp.CheckRevision("relay", tc.v, tc.least)
			if tc.want == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tc.want)
		})
	}
}

func TestRelaySession(t *testing.T) {
	welcome := &dp.SessionResponse{Msg: &dp.SessionResponse_Welcome{Welcome: &dp.Welcome{ReflexiveAddress: "203.0.113.7:40000", MaxLanes: 15}}}
	pushes := []*dp.SessionResponse{
		{Msg: &dp.SessionResponse_RouteDelta{RouteDelta: &dp.RouteDelta{
			Rev:    1,
			Add:    []*dp.Route{{Vpc: vpc, Prefix: "fd61:a0b:c00:1::/96", Origin: "att-2"}},
			Remove: []*dp.Route{{Vpc: vpc, Prefix: "10.1.0.0/16", Origin: "att-3"}},
		}}},
		{Msg: &dp.SessionResponse_NoRoute{NoRoute: &dp.NoRoute{Vpc: vpc, Address: "fd61:a0b:c00:2::9"}}},
		{Msg: &dp.SessionResponse_Rekey{Rekey: rekey}},
		{Msg: &dp.SessionResponse_Config{Config: &dp.Config{Vpc: vpc, Mtu: 1280, DnsServers: []string{"fd61:a0b:c00::53"}, DnsSearchDomains: []string{"vpc.internal"}}}},
		{Msg: &dp.SessionResponse_Drain{Drain: &dp.Drain{Alternates: []*dp.RelayRef{relay}}}},
		{Msg: &dp.SessionResponse_RxReport{RxReport: &dp.RxReport{Sas: []*dp.SAStats{{Spi: 0x80000003, Packets: 70, Seq: 100}}}}},
		{Msg: &dp.SessionResponse_Revocations{Revocations: &dp.Revocations{Vpc: vpc, Agents: []*dp.RevokedAgent{
			{Name: "laptop", RevokedAt: timestamppb.New(time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC))},
		}}}},
		{Msg: &dp.SessionResponse_Revocations{Revocations: &dp.Revocations{Vpc: vpc}}},
	}
	up := []proto.Message{
		&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{Mode: dp.Mode_MODE_PSP, MaxVpcsPerSession: 1}}},
		&dp.SessionRequest{Msg: &dp.SessionRequest_Ack{Ack: &dp.Ack{Rev: 1}}},
		&dp.SessionRequest{Msg: &dp.SessionRequest_Status{Status: &dp.Status{IcvFailures: []*dp.ICVFailures{{Spi: sa.Spi, Count: 17}}}}},
	}
	r := &relayStub{stub: newStub(), welcome: welcome, pushes: pushes}
	mux := rpc.NewMux()
	dp.RegisterRelayServer(mux, r)
	agent, _ := connect(t, dp.ALPNRelay, nil, mux)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := dp.NewRelayClient(agent).Session(ctx)
	require.NoError(t, err)
	require.NoError(t, st.Send(up[0].(*dp.SessionRequest)))
	got, err := st.Recv()
	require.NoError(t, err)
	assert.Empty(t, diff(welcome, got))
	// The relay pushes while the agent sends.
	for _, m := range up[1:] {
		require.NoError(t, st.Send(m.(*dp.SessionRequest)))
	}
	require.NoError(t, st.CloseSend())
	for _, want := range pushes {
		got, err := st.Recv()
		require.NoError(t, err)
		assert.Empty(t, diff(want, got))
	}
	_, err = st.Recv()
	require.Equal(t, io.EOF, err)
	assert.Empty(t, diff(up, r.requests("Session")))
}

func TestRelayCalls(t *testing.T) {
	r := &relayStub{stub: newStub()}
	mux := rpc.NewMux()
	dp.RegisterRelayServer(mux, r)
	agent, _ := connect(t, dp.ALPNRelay, nil, mux)
	c := dp.NewRelayClient
	runCalls(t, agent, r.stub, []call{
		unary("Attach", c, dp.RelayClient.Attach,
			&dp.AttachRequest{Vpc: vpc, Name: "laptop", Labels: map[string]string{"env": "dev"}, Routes: []string{"10.1.0.0/16"}},
			&dp.AttachResponse{AttachmentId: "att-1", Addresses: []string{"fd61:a0b:c00:1::/96"}}),
		unary("Detach", c, dp.RelayClient.Detach, &dp.DetachRequest{AttachmentId: "att-1"}, &emptypb.Empty{}),
		unary("Detach unknown", c, dp.RelayClient.Detach, &dp.DetachRequest{AttachmentId: "att-9"}, rpc.Errorf(rpc.NotFound, "no attachment")),
		unary("Rekey", c, dp.RelayClient.Rekey, offer, &dp.KeysResponse{}),
		unary("RegisterLanes", c, dp.RelayClient.RegisterLanes, &dp.RegisterLanesRequest{Ports: []uint32{40001, 40002}, Receive: true}, &emptypb.Empty{}),
		unary("RegisterLanes taken", c, dp.RelayClient.RegisterLanes, &dp.RegisterLanesRequest{Ports: []uint32{40003}},
			rpc.Errorf(rpc.AlreadyExists, "port 40003 is a source of another session")),
	})
}

func TestPeerCalls(t *testing.T) {
	c := dp.NewPeerClient
	list := []string{"fd61:a0b:c00:1::/96", "fd61:a0b:c01:7::/96"}
	runBothWays(t, dp.ALPNPeer, func(m *rpc.Mux, s *stub) { dp.RegisterPeerServer(m, peerStub{s}) }, []call{
		unary("Hello", c, dp.PeerClient.Hello,
			&dp.PeerHello{Version: dp.LocalVersion("build-a"), Prefixes: list, Instance: 0x6f1c2a8e3b4d4c5e},
			&dp.PeerHello{Version: dp.LocalVersion("build-b"), Prefixes: []string{"fd61:a0b:c00:2::/96"}, Instance: 0x0e4f5a6b7c8d4e9f}),
		unary("Keys", c, dp.PeerClient.Keys, offer, &dp.KeysResponse{RefusedSpis: []uint32{sa.Spi}}),
		unary("Keys rekey", c, dp.PeerClient.Keys, rekey, &dp.KeysResponse{}),
		unary("Candidates", c, dp.PeerClient.Candidates,
			&dp.Candidates{Round: 2, Addresses: []string{"198.51.100.7:40000", "[2001:db8::7]:40000"}, Prefixes: list},
			&emptypb.Empty{}),
	})
}

func TestMeshCalls(t *testing.T) {
	c := dp.NewMeshClient
	runBothWays(t, dp.ALPNMesh, func(m *rpc.Mux, s *stub) { dp.RegisterMeshServer(m, meshStub{s}) }, []call{
		unary("Open", c, dp.MeshClient.Open,
			&dp.MeshOpenRequest{Version: dp.LocalVersion("build-a"), Name: "relay-a-0", Relay: &dp.RelayRef{Id: "relay-a", Addresses: []string{"198.51.100.1:443"}}},
			&dp.MeshOpenResponse{Version: dp.LocalVersion("build-b"), Name: "relay-b-0", Relay: relay}),
		unary("Open not a member", c, dp.MeshClient.Open,
			&dp.MeshOpenRequest{Version: dp.LocalVersion("build-a"), Name: "relay-c-0"},
			rpc.Errorf(rpc.PermissionDenied, "relay relay-c-0 is not a member")),
		bidiStream("Presence", c, dp.MeshClient.Presence, &dp.PresenceControl{Ack: 3},
			&dp.PresenceUpdate{Seq: 1, Vpcs: []*dp.VPCRef{vpc}, EndOfVpcs: true},
			&dp.PresenceUpdate{Seq: 2, Parts: []*dp.PresencePart{{Vpc: vpc, EndOfFullSet: true, Entries: []*dp.Presence{{
				Vpc: vpc, AttachmentId: "att-1", Generation: 1, Prefixes: []string{"fd61:a0b:c00:1::/96"},
				Subject: "spiffe://p-1/vpc/u-1/agent/laptop", AgentName: "base", SenderTag: 1<<24 - 1,
			}}}}},
			&dp.PresenceUpdate{Seq: 3, Parts: []*dp.PresencePart{{Vpc: vpc, Entries: []*dp.Presence{{AttachmentId: "att-1", Generation: 2, Gone: true}}}}}),
		unary("TrunkKeys", c, dp.MeshClient.TrunkKeys, offer, &dp.KeysResponse{}),
		serverStream("Snapshot", c, dp.MeshClient.Snapshot, &dp.SnapshotRequest{},
			&dp.SnapshotPart{Data: []byte("bytes of the host"), TotalSize: 17}),
		serverStream("Snapshot of a host with none", c, dp.MeshClient.Snapshot, &dp.SnapshotRequest{},
			rpc.Errorf(rpc.NotFound, "relay host has no snapshot")),
	})
}

// TestJSONDebug calls a relay handler through the JSON debug handler, as curl does.
func TestJSONDebug(t *testing.T) {
	r := &relayStub{stub: newStub()}
	mux := rpc.NewMux()
	dp.RegisterRelayServer(mux, r)
	srv := httptest.NewServer(rpc.JSONHandler(mux))
	defer srv.Close()
	r.expect("Attach", &dp.AttachResponse{AttachmentId: "att-1", Addresses: []string{"fd61:a0b:c00:1::/96"}})

	body := `{"vpc":{"project_id":"p-1","vpc_uid":"u-1","network_id":658188},"name":"laptop","routes":["fd61:a0b:c00:2::/96"]}`
	resp, err := http.Post(srv.URL+dp.Relay_Attach_FullMethodName, "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", out)
	assert.JSONEq(t, `{"attachmentId":"att-1","addresses":["fd61:a0b:c00:1::/96"]}`, string(out))
	want := &dp.AttachRequest{Vpc: &dp.VPCRef{ProjectId: "p-1", VpcUid: "u-1", NetworkId: 0x0a0b0c}, Name: "laptop", Routes: []string{"fd61:a0b:c00:2::/96"}}
	assert.Empty(t, diff([]proto.Message{want}, r.requests("Attach")))
}
