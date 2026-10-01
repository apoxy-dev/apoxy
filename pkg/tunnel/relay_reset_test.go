package tunnel_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/hasher"
)

// TestRelay_StatelessResetAfterRestart restarts a relay on the same address.
// Only the same secret, the same name and a packet over 42 bytes give a reset.
func TestRelay_StatelessResetAfterRestart(t *testing.T) {
	const (
		secret = "relay-id-secret"
		relay  = "relay-a"
	)
	cases := []struct {
		name        string
		secretAfter string
		relayAfter  string
		write       bool
		wantReset   bool
	}{
		{name: "same relay, packet over 42 bytes", secretAfter: secret, relayAfter: relay, write: true, wantReset: true},
		{name: "same relay, keepalive only", secretAfter: secret, relayAfter: relay},
		{name: "different secret", secretAfter: "other-relay-id-secret", relayAfter: relay, write: true},
		{name: "different relay name", secretAfter: secret, relayAfter: "relay-b", write: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			old := &crashConn{PacketConn: pc}
			caCert := startRelayWithSecret(t, old, relay, secret)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{
				RootCAs:    cryptoutils.CertPoolForCertificate(caCert),
				ServerName: "localhost",
				NextProtos: []string{http3.NextProtoH3},
			}, &quic.Config{MaxIdleTimeout: 2 * time.Second, KeepAlivePeriod: 500 * time.Millisecond})
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			// After the relay control stream, client packets have a short header.
			_, err = conn.AcceptUniStream(ctx)
			require.NoError(t, err)

			old.crash()
			pc2, err := net.ListenPacket("udp", pc.LocalAddr().String())
			require.NoError(t, err)
			startRelayWithSecret(t, pc2, tc.relayAfter, tc.secretAfter)

			if tc.write {
				str, err := conn.OpenStream()
				require.NoError(t, err)
				_, err = str.Write(make([]byte, 200))
				require.NoError(t, err)
			}

			select {
			case <-conn.Context().Done():
			case <-ctx.Done():
				t.Fatal("client connection did not close")
			}
			cause := context.Cause(conn.Context())
			if tc.wantReset {
				var reset *quic.StatelessResetError
				require.ErrorAs(t, cause, &reset)
			} else {
				var idle *quic.IdleTimeoutError
				require.ErrorAs(t, cause, &idle)
			}
		})
	}
}

func TestRelay_StatelessResetSecretEmpty(t *testing.T) {
	r := tunnel.NewRelay("relay-a", nil, tls.Certificate{}, nil, nil, nil)
	require.Error(t, r.SetStatelessResetSecret(nil))
}

// crashConn is a relay socket that sends nothing after crash.
type crashConn struct {
	net.PacketConn
	dead atomic.Bool
}

func (c *crashConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.dead.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *crashConn) crash() {
	c.dead.Store(true)
	_ = c.PacketConn.Close()
}

// startRelayWithSecret starts a relay on pc and returns its CA cert.
func startRelayWithSecret(t *testing.T, pc net.PacketConn, name, secret string) tls.Certificate {
	t.Helper()

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)
	h, err := icx.NewHandler(
		icx.WithLocalAddr(netstack.ToFullAddress(netip.MustParseAddrPort("127.0.0.1:6081"))),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)
	idKey := make([]byte, 32)
	_, err = rand.Read(idKey)
	require.NoError(t, err)

	rtr := &mockRouter{}
	rtr.On("Start", mock.Anything).Return(nil)
	rtr.On("Close").Return(nil)

	r := tunnel.NewRelay(name, pc, serverCert, h, hasher.NewHasher(idKey), rtr)
	require.NoError(t, r.SetStatelessResetSecret([]byte(secret)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// A crashed relay stops with a socket error.
		_ = r.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		_ = pc.Close()
	})
	return caCert
}
