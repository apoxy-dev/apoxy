package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
)

func TestStatelessResetKey(t *testing.T) {
	base, err := statelessResetKey([]byte("secret"), "tunnelproxy", "node-a")
	require.NoError(t, err)

	cases := []struct {
		name     string
		secret   string
		role     string
		server   string
		wantSame bool
		wantErr  bool
	}{
		{name: "same inputs", secret: "secret", role: "tunnelproxy", server: "node-a", wantSame: true},
		{name: "different secret", secret: "other", role: "tunnelproxy", server: "node-a"},
		{name: "different role", secret: "secret", role: "relay", server: "node-a"},
		{name: "different name", secret: "secret", role: "tunnelproxy", server: "node-b"},
		{name: "empty secret", role: "tunnelproxy", server: "node-a", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := statelessResetKey([]byte(tc.secret), tc.role, tc.server)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantSame, *key == *base)
		})
	}
}

// TestStatelessResetKey_Relay checks that the relay key does not change.
func TestStatelessResetKey_Relay(t *testing.T) {
	r := &Relay{name: "node-a"}
	require.NoError(t, r.SetStatelessResetSecret([]byte("secret")))
	key, err := statelessResetKey([]byte("secret"), "relay", "node-a")
	require.NoError(t, err)
	require.Equal(t, *key, *r.resetKey)
}

// TestTunnelServer_StatelessResetAfterRestart restarts a tunnel server on the
// same address and compares the reset tokens for one connection ID.
func TestTunnelServer_StatelessResetAfterRestart(t *testing.T) {
	const (
		secret = "reset-secret"
		server = "node-a"
	)
	cases := []struct {
		name        string
		secretAfter string
		serverAfter string
		wantReset   bool
		wantSame    bool
	}{
		{name: "same secret and name", secretAfter: secret, serverAfter: server, wantReset: true, wantSame: true},
		{name: "different secret", secretAfter: "other-secret", serverAfter: server, wantReset: true},
		{name: "different name", secretAfter: secret, serverAfter: "node-b", wantReset: true},
		{name: "no secret", serverAfter: server},
	}

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)
	certsDir := t.TempDir()
	require.NoError(t, cryptoutils.SaveCertificatePEM(serverCert, certsDir, "server", false))
	certs := resetTestCerts{dir: certsDir, ca: caCert}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			addr := pc.LocalAddr().String()
			require.NoError(t, pc.Close())

			stop := startResetTestServer(t, certs, addr, secret, server)
			before := resetToken(t, addr)
			require.NotNil(t, before, "the first server sent no reset")
			stop()

			stop = startResetTestServer(t, certs, addr, tc.secretAfter, tc.serverAfter)
			defer stop()
			after := resetToken(t, addr)
			if !tc.wantReset {
				require.Nil(t, after)
				return
			}
			require.NotNil(t, after, "the restarted server sent no reset")
			require.Equal(t, tc.wantSame, string(before) == string(after))
		})
	}
}

type resetTestCerts struct {
	dir string
	ca  tls.Certificate
}

// startResetTestServer starts a tunnel server on addr and waits until it
// accepts a QUIC connection. An empty secret sends no resets.
func startResetTestServer(t *testing.T, certs resetTestCerts, addr, secret, name string) (stop func()) {
	t.Helper()
	opts := []TunnelServerOption{
		WithProxyAddr(addr),
		WithCertPath(filepath.Join(certs.dir, "server.crt")),
		WithKeyPath(filepath.Join(certs.dir, "server.key")),
	}
	if secret != "" {
		opts = append(opts, WithStatelessResetSecret([]byte(secret), name))
	}
	srv, err := NewTunnelServer(nil, nil, &stubRouter{}, opts...)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	tlsConf := &tls.Config{
		RootCAs:    cryptoutils.CertPoolForCertificate(certs.ca),
		ServerName: "localhost",
		NextProtos: []string{http3.NextProtoH3},
	}
	require.Eventually(t, func() bool {
		dialCtx, dialCancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer dialCancel()
		conn, err := quic.DialAddr(dialCtx, addr, tlsConf, nil)
		if err != nil {
			return false
		}
		_ = conn.CloseWithError(0, "")
		return true
	}, 5*time.Second, 50*time.Millisecond, "the tunnel server did not start")

	return func() {
		cancel()
		require.NoError(t, srv.Stop())
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("the tunnel server did not stop")
		}
	}
}

// resetToken sends a short header packet over 42 bytes for an unknown
// connection ID to addr. It returns the token of the reset, or nil.
func resetToken(t *testing.T, addr string) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	require.NoError(t, err)
	defer c.Close()

	p := make([]byte, 64)
	p[0] = 0x40
	copy(p[1:], "cid0")
	_, err = c.Write(p)
	require.NoError(t, err)

	require.NoError(t, c.SetReadDeadline(time.Now().Add(time.Second)))
	b := make([]byte, 1500)
	n, err := c.Read(b)
	if err != nil {
		return nil
	}
	require.GreaterOrEqual(t, n, 16+5)
	return b[n-16 : n]
}
