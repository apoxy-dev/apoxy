package kex_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/kex"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"

	"math/big"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestServer(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	issuer, err := token.NewIssuer(privateKeyPEM)
	require.NoError(t, err)

	validator, err := token.NewInMemoryValidator(publicKeyPEM)
	require.NoError(t, err)

	tokenStr, _, err := issuer.IssueToken("test-agent", time.Minute*5)
	require.NoError(t, err)

	handler, err := icx.NewHandler(
		icx.WithLocalAddr(mustNewFullAddress("127.0.0.1", 6081)),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)

	serverImpl := kex.NewServer(t.Context(), handler, validator, 100*time.Millisecond)
	httpHandler := serverImpl.Routes()

	// Bind UDP socket and build a quic.Transport on it.
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = udpConn.Close() })

	qt := &quic.Transport{Conn: udpConn}

	// Self-signed TLS certificate for localhost (required for QUIC).
	serverTLS, err := generateHTTP3TLSConfig()
	require.NoError(t, err)

	// Ensure ALPN is configured for HTTP/3.
	serverTLS = http3.ConfigureTLSConfig(serverTLS)

	// Create a QUIC EarlyListener bound to our UDP socket.
	qln, err := qt.ListenEarly(serverTLS, &quic.Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qln.Close() })

	// Start the HTTP/3 server using the QUIC listener.
	h3Server := &http3.Server{
		Handler: httpHandler,
	}
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- h3Server.ServeListener(qln)
	}()
	t.Cleanup(func() {
		_ = h3Server.Close()
		select {
		case <-serverErrCh:
		default:
		}
	})

	// Server base URL (scheme must be https).
	serverAddr := qln.Addr().String()
	baseURL := "https://" + serverAddr

	// In tests, skip verification for the self-signed cert.
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}

	client := kex.NewClient(baseURL, tokenStr, clientTLS, nil)
	t.Cleanup(func() { _ = client.Close() })

	// Raw HTTP/3 client (no auth header) for the "Requires Authorization" test.
	rawRT := &http3.Transport{
		TLSClientConfig: clientTLS,
	}
	t.Cleanup(func() { _ = rawRT.Close() })
	rawHTTP := &http.Client{Transport: rawRT, Timeout: 10 * time.Second}

	t.Run("Requires Authorization", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, baseURL+"/network", nil)
		require.NoError(t, err)

		resp, err := rawHTTP.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Connect", func(t *testing.T) {
		connectResp, err := client.Connect(t.Context(), "127.0.0.1:6081")
		require.NoError(t, err)

		assert.NotEmpty(t, connectResp.Keys.Send)
		assert.NotEmpty(t, connectResp.Keys.Recv)
		assert.Equal(t, 1, connectResp.Keys.Epoch)
		assert.Equal(t, 1, len(connectResp.Addresses))
	})

	t.Run("Disconnect", func(t *testing.T) {
		connectResp, err := client.Connect(t.Context(), "127.0.0.1:6081")
		require.NoError(t, err)

		err = client.Disconnect(t.Context(), connectResp.NetworkID)
		require.NoError(t, err)
	})

	t.Run("RenewKeys", func(t *testing.T) {
		connectResp, err := client.Connect(t.Context(), "127.0.0.1:6081")
		require.NoError(t, err)

		renewResp, err := client.RenewKeys(t.Context(), connectResp.NetworkID)
		require.NoError(t, err)

		assert.Equal(t, 2, renewResp.Keys.Epoch)
		assert.NotEmpty(t, renewResp.Keys.Send)
		assert.NotEmpty(t, renewResp.Keys.Recv)
	})

	t.Run("ExpiredNetworkCleanup", func(t *testing.T) {
		connectResp, err := client.Connect(t.Context(), "127.0.0.1:6081")
		require.NoError(t, err)

		// Wait for the network to expire
		time.Sleep(time.Second)

		serverImpl.CleanupExpiredNetworks()

		// Attempt to disconnect after expiry
		err = client.Disconnect(t.Context(), connectResp.NetworkID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disconnect failed")
	})
}

func mustNewFullAddress(ip string, port uint16) *tcpip.FullAddress {
	netAddr := netip.MustParseAddr(ip)

	switch netAddr.BitLen() {
	case 32:
		addr := tcpip.AddrFrom4Slice(netAddr.AsSlice())
		return &tcpip.FullAddress{
			Addr: addr,
			Port: port,
		}
	case 128:
		addr := tcpip.AddrFrom16Slice(netAddr.AsSlice())
		return &tcpip.FullAddress{
			Addr: addr,
			Port: port,
		}
	default:
		panic("Unsupported IP address length")
	}
}

func generateHTTP3TLSConfig() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
		},
		DNSNames: []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // QUIC requires TLS 1.3
	}, nil
}
