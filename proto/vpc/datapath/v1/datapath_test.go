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
	accepted := make(chan quic.Connection, 1)
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

// recvAll records each message of a client stream.
func recvAll[Req any](s *stub, method string, st rpc.ClientStreamServer[Req]) (*emptypb.Empty, error) {
	for {
		in, err := st.Recv()
		if err == io.EOF {
			return &emptypb.Empty{}, nil
		}
		if err != nil {
			return nil, err
		}
		s.record(method, any(in).(proto.Message))
	}
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

func (r *relayStub) Rekey(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	return answer[*dp.KeysResponse](r.stub, "Rekey", in)
}

func (r *relayStub) ResolvePeer(ctx context.Context, in *dp.ResolvePeerRequest) (*dp.ResolvePeerResponse, error) {
	return answer[*dp.ResolvePeerResponse](r.stub, "ResolvePeer", in)
}

func (r *relayStub) RegisterSPI(ctx context.Context, in *dp.RegisterSPIRequest) (*emptypb.Empty, error) {
	return answer[*emptypb.Empty](r.stub, "RegisterSPI", in)
}

func (r *relayStub) UnregisterSPI(ctx context.Context, in *dp.UnregisterSPIRequest) (*emptypb.Empty, error) {
	return answer[*emptypb.Empty](r.stub, "UnregisterSPI", in)
}

type peerStub struct{ *stub }

func (p peerStub) Open(ctx context.Context, in *dp.OpenRequest) (*dp.OpenResponse, error) {
	return answer[*dp.OpenResponse](p.stub, "Open", in)
}

func (p peerStub) Keys(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	return answer[*dp.KeysResponse](p.stub, "Keys", in)
}

func (p peerStub) Paths(ctx context.Context, st rpc.ClientStreamServer[dp.Candidates]) (*emptypb.Empty, error) {
	return recvAll(p.stub, "Paths", st)
}

type meshStub struct{ *stub }

func (m meshStub) Presence(ctx context.Context, st rpc.ClientStreamServer[dp.PresenceUpdate]) (*emptypb.Empty, error) {
	return recvAll(m.stub, "Presence", st)
}

func (m meshStub) SPIRows(ctx context.Context, st rpc.ClientStreamServer[dp.SPIRowUpdate]) (*emptypb.Empty, error) {
	return recvAll(m.stub, "SPIRows", st)
}

func (m meshStub) TrunkKeys(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	return answer[*dp.KeysResponse](m.stub, "TrunkKeys", in)
}

// Test messages.
var (
	vpc    = &dp.VPCRef{ProjectId: "11111111-2222-3333-4444-555555555555", VpcUid: "vpc-uid-1", NetworkId: 0x0a0b0c}
	relay  = &dp.RelayRef{Id: "relay-b", Addresses: []string{"198.51.100.2:443", "[2001:db8::2]:443"}}
	sa     = &dp.SA{Spi: 0x8000_1234, Key: bytes.Repeat([]byte{7}, 16), Vni: 0x0a0b0c, ExpiresIn: durationpb.New(10 * time.Minute), Lane: 3}
	grant  = &dp.AttachmentGrant{Claims: []byte("claims"), Signature: []byte("signature")}
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

func clientStream[C, Req, Res any](name string, client func(rpc.Caller) C, open func(C, context.Context) (rpc.ClientStreamClient[Req, Res], error), in ...*Req) call {
	tc := call{name: name, answer: &emptypb.Empty{}}
	for _, m := range in {
		tc.sent = append(tc.sent, any(m).(proto.Message))
	}
	tc.do = func(ctx context.Context, c *rpc.Conn) (proto.Message, error) {
		st, err := open(client(c), ctx)
		if err != nil {
			return nil, err
		}
		for _, m := range in {
			if err := st.Send(m); err != nil {
				return nil, err
			}
		}
		out, err := st.CloseAndRecv()
		return any(out).(proto.Message), err
	}
	return tc
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

func TestRelaySession(t *testing.T) {
	welcome := &dp.SessionResponse{Msg: &dp.SessionResponse_Welcome{Welcome: &dp.Welcome{ReflexiveAddress: "203.0.113.7:40000"}}}
	pushes := []*dp.SessionResponse{
		{Msg: &dp.SessionResponse_RouteDelta{RouteDelta: &dp.RouteDelta{
			Rev:    1,
			Add:    []*dp.Route{{Vpc: vpc, Prefix: "fd61:a0b:c00:1::/96", Origin: "att-2"}},
			Remove: []*dp.Route{{Vpc: vpc, Prefix: "10.1.0.0/16", Origin: "att-3"}},
		}}},
		{Msg: &dp.SessionResponse_NoRoute{NoRoute: &dp.NoRoute{Vpc: vpc, Address: "fd61:a0b:c00:2::9", HomeRelay: relay}}},
		{Msg: &dp.SessionResponse_Rekey{Rekey: rekey}},
		{Msg: &dp.SessionResponse_Config{Config: &dp.Config{Vpc: vpc, Mtu: 1280, DnsServers: []string{"fd61:a0b:c00::53"}, DnsSearchDomains: []string{"vpc.internal"}}}},
		{Msg: &dp.SessionResponse_Drain{Drain: &dp.Drain{Alternates: []*dp.RelayRef{relay}}}},
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
			&dp.AttachResponse{AttachmentId: "att-1", Grant: grant}),
		unary("Rekey", c, dp.RelayClient.Rekey, offer, &dp.KeysResponse{}),
		unary("ResolvePeer visit", c, dp.RelayClient.ResolvePeer,
			&dp.ResolvePeerRequest{Vpc: vpc, Address: "fd61:a0b:c00:2::9"},
			&dp.ResolvePeerResponse{Reach: dp.Reach_REACH_VISIT, HomeRelay: relay, P2P: true}),
		unary("ResolvePeer denied", c, dp.RelayClient.ResolvePeer,
			&dp.ResolvePeerRequest{Vpc: vpc, Address: "fd61:a0b:c00:3::9"},
			rpc.Errorf(rpc.PermissionDenied, "permit denies")),
		unary("RegisterSPI", c, dp.RelayClient.RegisterSPI,
			&dp.RegisterSPIRequest{Vpc: vpc, Destination: "fd61:a0b:c00:2::9", Spis: []uint32{sa.Spi}, ExpiresIn: durationpb.New(5 * time.Minute)},
			&emptypb.Empty{}),
		unary("UnregisterSPI", c, dp.RelayClient.UnregisterSPI,
			&dp.UnregisterSPIRequest{Vpc: vpc, Spis: []uint32{sa.Spi}}, &emptypb.Empty{}),
	})
}

func TestPeerCalls(t *testing.T) {
	c := dp.NewPeerClient
	runBothWays(t, dp.ALPNPeer, func(m *rpc.Mux, s *stub) { dp.RegisterPeerServer(m, peerStub{s}) }, []call{
		unary("Open", c, dp.PeerClient.Open,
			&dp.OpenRequest{Grant: grant, Instance: 0x0102030405060708, Mode: dp.Mode_MODE_PSP, P2P: true},
			&dp.OpenResponse{Grant: grant, Instance: 0x1112131415161718, Mode: dp.Mode_MODE_QUIC}),
		unary("Keys offer", c, dp.PeerClient.Keys, offer, &dp.KeysResponse{RefusedSpis: []uint32{sa.Spi}}),
		unary("Keys rekey", c, dp.PeerClient.Keys, rekey, &dp.KeysResponse{}),
		unary("Keys revoke", c, dp.PeerClient.Keys, revoke, &dp.KeysResponse{}),
		clientStream("Paths", c, dp.PeerClient.Paths,
			&dp.Candidates{Round: 1, Mtu: 1280, Candidates: []*dp.Candidate{
				{Kind: dp.CandidateKind_CANDIDATE_KIND_HOST, Address: "2001:db8::10", Port: 41641},
				{Kind: dp.CandidateKind_CANDIDATE_KIND_REFLEXIVE, Address: "203.0.113.7", Port: 40000},
			}},
			&dp.Candidates{Round: 2, Mtu: 1280}),
	})
}

func TestMeshCalls(t *testing.T) {
	c := dp.NewMeshClient
	runBothWays(t, dp.ALPNMesh, func(m *rpc.Mux, s *stub) { dp.RegisterMeshServer(m, meshStub{s}) }, []call{
		clientStream("Presence", c, dp.MeshClient.Presence,
			&dp.PresenceUpdate{Entries: []*dp.Presence{{Vpc: vpc, AttachmentId: "att-1", Generation: 1, Prefixes: []string{"fd61:a0b:c00:1::/96"}}}},
			&dp.PresenceUpdate{Entries: []*dp.Presence{{Vpc: vpc, AttachmentId: "att-1", Generation: 2, Gone: true}}}),
		clientStream("SPIRows", c, dp.MeshClient.SPIRows,
			&dp.SPIRowUpdate{Rows: []*dp.SPIRow{{Vpc: vpc, SenderTag: 9, Spi: sa.Spi, Destination: "fd61:a0b:c00:2::9", ExpiresIn: durationpb.New(5 * time.Minute)}}},
			&dp.SPIRowUpdate{Rows: []*dp.SPIRow{{Vpc: vpc, SenderTag: 9, Spi: sa.Spi, Removed: true}}}),
		unary("TrunkKeys", c, dp.MeshClient.TrunkKeys, offer, &dp.KeysResponse{}),
	})
}

// TestJSONDebug calls a relay handler through the JSON debug handler, as curl does.
func TestJSONDebug(t *testing.T) {
	r := &relayStub{stub: newStub()}
	mux := rpc.NewMux()
	dp.RegisterRelayServer(mux, r)
	srv := httptest.NewServer(rpc.JSONHandler(mux))
	defer srv.Close()
	r.expect("ResolvePeer", &dp.ResolvePeerResponse{Reach: dp.Reach_REACH_TRUNK, P2P: true})

	body := `{"vpc":{"project_id":"p-1","vpc_uid":"u-1","network_id":658188},"address":"fd61:a0b:c00:2::9"}`
	resp, err := http.Post(srv.URL+dp.Relay_ResolvePeer_FullMethodName, "application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", out)
	assert.JSONEq(t, `{"reach":"REACH_TRUNK","p2p":true}`, string(out))
	want := &dp.ResolvePeerRequest{Vpc: &dp.VPCRef{ProjectId: "p-1", VpcUid: "u-1", NetworkId: 0x0a0b0c}, Address: "fd61:a0b:c00:2::9"}
	assert.Empty(t, diff([]proto.Message{want}, r.requests("ResolvePeer")))
}
