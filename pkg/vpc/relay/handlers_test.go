// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	os.Exit(m.Run())
}

var vpc = &dp.VPCRef{ProjectId: "project-a", VpcUid: "vpc-1", NetworkId: 0x0a0b0c}

// harness is a relay that serves the Relay service on loopback QUIC.
type harness struct {
	r         *relay.Router
	mux       *rpc.Mux
	ln        *quic.Listener
	clientTLS *tls.Config
	wg        sync.WaitGroup
}

func newHarness(t *testing.T) *harness {
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
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{dp.ALPNRelay},
	}, nil)
	require.NoError(t, err)
	h := &harness{
		r:         relay.NewRouter(relay.Config{}),
		mux:       rpc.NewMux(),
		ln:        ln,
		clientTLS: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{dp.ALPNRelay}},
	}
	dp.RegisterRelayServer(h.mux, relay.Server{R: h.r})
	t.Cleanup(func() {
		_ = ln.Close()
		h.wg.Wait()
	})
	return h
}

// agent is one agent connection to the relay.
type agent struct {
	c    dp.RelayClient
	qc   quic.Connection
	sess *relay.Session // Nil if the relay did not add a session.
	src  netip.AddrPort // Source address as the relay sees it.
}

// dial connects an agent. The relay adds a session with id if it is not nil.
func (h *harness) dial(t *testing.T, id *relay.Identity) agent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan quic.Connection, 1)
	go func() {
		c, _ := h.ln.Accept(ctx)
		accepted <- c
	}()
	// Dial from 127.0.0.1. On macOS the wildcard socket of DialAddr can get a
	// port that a 127.0.0.1 socket holds, and the replies then go to that socket.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	dq, err := quic.Dial(ctx, udp, h.ln.Addr(), h.clientTLS, nil)
	require.NoError(t, err)
	lq := <-accepted
	require.NotNil(t, lq)
	lc := rpc.NewConn(lq, h.mux)
	a := agent{c: dp.NewRelayClient(rpc.NewConn(dq, nil)), qc: dq, src: netip.MustParseAddrPort(lq.RemoteAddr().String())}
	if id != nil {
		a.sess, err = h.r.AddSession(lc, *id)
		require.NoError(t, err)
	}
	h.wg.Go(func() { _ = lc.Serve(context.Background()) })
	t.Cleanup(func() {
		_ = dq.CloseWithError(0, "")
		_ = lq.CloseWithError(0, "")
		_ = udp.Close()
	})
	return a
}

func TestOverQUIC(t *testing.T) {
	h := newHarness(t)
	key := relay.VPCKey{Project: vpc.ProjectId, UID: vpc.VpcUid}
	snd := h.dial(t, &relay.Identity{VPC: key, ID: "spiffe://project-a/vpc/vpc-1/agent/sender"})
	recv := h.dial(t, &relay.Identity{VPC: key, ID: "spiffe://project-a/vpc/vpc-1/agent/receiver"})
	require.NoError(t, h.r.AddRoute(recv.sess, netip.MustParsePrefix("fd00::2/128")))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := snd.c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: vpc, Address: "fd00::2"})
	require.NoError(t, err)
	assert.Equal(t, dp.Reach_REACH_LOCAL, res.Reach)
	assert.True(t, res.P2P)

	_, err = snd.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{Vpc: vpc, Destination: "fd00::2", Spis: []uint32{7}, ExpiresIn: durationpb.New(time.Minute)})
	require.NoError(t, err)
	// The relay takes the sender from the authenticated connection.
	dst, v := h.r.Forward(snd.src, 7, 1400, time.Now())
	require.Equal(t, relay.Pass, v)
	assert.Equal(t, recv.src, dst)
	_, v = h.r.Forward(recv.src, 7, 1400, time.Now())
	assert.Equal(t, relay.DropUnknownSPI, v)

	_, err = snd.c.UnregisterSPI(ctx, &dp.UnregisterSPIRequest{Vpc: vpc, Spis: []uint32{7}})
	require.NoError(t, err)
	_, v = h.r.Forward(snd.src, 7, 1400, time.Now())
	assert.Equal(t, relay.DropUnknownSPI, v)

	// The session and its rows end when the connection closes.
	_, err = snd.c.RegisterSPI(ctx, &dp.RegisterSPIRequest{Vpc: vpc, Destination: "fd00::2", Spis: []uint32{8}, ExpiresIn: durationpb.New(time.Minute)})
	require.NoError(t, err)
	require.NoError(t, snd.qc.CloseWithError(0, ""))
	require.Eventually(t, func() bool {
		_, v := h.r.Forward(snd.src, 8, 1400, time.Now())
		return v == relay.DropUnknownSource
	}, 5*time.Second, 10*time.Millisecond)
	assert.Empty(t, h.r.SenderStats(snd.sess).Lanes)
}

// TestUnauthenticated checks that each call that needs the caller identity
// fails with Unauthenticated when there is no session: from the JSON debug
// handler (no Conn) and from a connection that the relay did not add.
func TestUnauthenticated(t *testing.T) {
	h := newHarness(t)
	stranger := h.dial(t, nil)
	srv := httptest.NewServer(rpc.JSONHandler(h.mux))
	defer srv.Close()
	reg := &dp.RegisterSPIRequest{Vpc: vpc, Destination: "fd00::2", Spis: []uint32{7}, ExpiresIn: durationpb.New(time.Minute)}

	cases := []struct {
		method string
		json   string
		call   func(ctx context.Context, c dp.RelayClient) error
	}{
		{dp.Relay_ResolvePeer_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"address":"fd00::2"}`,
			func(ctx context.Context, c dp.RelayClient) error {
				_, err := c.ResolvePeer(ctx, &dp.ResolvePeerRequest{Vpc: vpc, Address: "fd00::2"})
				return err
			}},
		{dp.Relay_RegisterSPI_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"destination":"fd00::2","spis":[7],"expiresIn":"60s"}`,
			func(ctx context.Context, c dp.RelayClient) error {
				_, err := c.RegisterSPI(ctx, reg)
				return err
			}},
		{dp.Relay_UnregisterSPI_FullMethodName, `{"vpc":{"projectId":"project-a","vpcUid":"vpc-1"},"spis":[7]}`,
			func(ctx context.Context, c dp.RelayClient) error {
				_, err := c.UnregisterSPI(ctx, &dp.UnregisterSPIRequest{Vpc: vpc, Spis: []uint32{7}})
				return err
			}},
	}
	for _, tc := range cases {
		t.Run(tc.method[strings.LastIndex(tc.method, "/")+1:], func(t *testing.T) {
			resp, err := http.Post(srv.URL+tc.method, "application/json", strings.NewReader(tc.json))
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "JSON debug handler")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			assert.Equal(t, rpc.Unauthenticated, rpc.CodeOf(tc.call(ctx, stranger.c)), "connection with no session")
		})
	}
}
