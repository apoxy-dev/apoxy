package endpointselect

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
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startPingServer runs a minimal HTTP/3 server answering GET /ping on
// loopback and returns its address.
func startPingServer(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{http3.NextProtoH3},
		},
	}
	go srv.Serve(udpConn)
	t.Cleanup(func() {
		srv.Close()
		udpConn.Close()
	})
	return udpConn.LocalAddr().String()
}

// startBlackholeEndpoint binds a UDP socket that never answers, so a QUIC
// dial against it blocks until the probe timeout.
func startBlackholeEndpoint(t *testing.T) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })
	return udpConn.LocalAddr().String()
}

// TestLatencySelector_EarlyCancelOnlyInSelect pins the split contract: Select
// consumes a single winner so it may cancel the losers' probes as soon as one
// endpoint responds, but SelectWithResults feeds full-pool ranking (the tunnel
// agent's relay preference), where an early cancel corrupts every measurement
// except the winner's — cancelled probes either drop out of the ranking or
// report a single handshake-inflated ping.
func TestLatencySelector_EarlyCancelOnlyInSelect(t *testing.T) {
	const probeTimeout = 2 * time.Second
	fast := startPingServer(t)
	blackhole := startBlackholeEndpoint(t)
	sel := NewLatencySelector(
		WithProbeTimeout(probeTimeout),
		WithInsecureSkipVerify(true),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	t.Run("SelectWithResults probes every endpoint to completion", func(t *testing.T) {
		start := time.Now()
		addr, results, err := sel.SelectWithResults(ctx, []string{fast, blackhole})
		require.NoError(t, err)
		assert.Equal(t, fast, addr)
		assert.GreaterOrEqual(t, time.Since(start), probeTimeout,
			"the unreachable endpoint's probe must run out its own timeout, not be cancelled by the winner")

		byAddr := make(map[string]ProbeResult, len(results))
		for _, r := range results {
			byAddr[r.Addr] = r
		}
		require.NoError(t, byAddr[fast].Error)
		assert.Positive(t, byAddr[fast].Latency)
		require.Error(t, byAddr[blackhole].Error)
		assert.NotErrorIs(t, byAddr[blackhole].Error, context.Canceled,
			"the losing probe must fail on its own terms, not on the winner's cancel")
	})

	t.Run("Select cancels losers once a winner responds", func(t *testing.T) {
		start := time.Now()
		addr, err := sel.Select(ctx, []string{fast, blackhole})
		require.NoError(t, err)
		assert.Equal(t, fast, addr)
		assert.Less(t, time.Since(start), probeTimeout,
			"single-winner selection must not wait out the unreachable endpoint's timeout")
	})
}
