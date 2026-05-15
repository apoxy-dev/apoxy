package apiserviceproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/apoxy-dev/apoxy/pkg/cert"
)

// makeClientCertPEMWithExpiry mints a self-signed leaf usable as an mTLS
// client cert with a caller-specified NotAfter. Used to simulate both
// "healthy cert" (NotAfter far out) and "near-expiry cert" inputs to the
// renewer.
func makeClientCertPEMWithExpiry(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte, fp string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "kube-controller-renew-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	fp = cert.Fingerprint(parsed.Raw)
	return
}

// fakeCosmosServer stands in for cosmos's /v1/terra/serviceaccount/certificate
// endpoint. The handler verifies the request was mTLS-authenticated (peer
// cert presented) and returns a pre-minted leaf so the renewer can validate
// the swap end-to-end.
type fakeCosmosServer struct {
	srv          *httptest.Server
	requestCount atomic.Int32
	gotPeerCN    atomic.Value // string
	gotAPIKey    atomic.Value // string
	statusCode   atomic.Int32 // 0 → 200
	nextCertPEM  []byte
	nextKeyPEM   []byte
	nextFP       string
}

func newFakeCosmosServer(t *testing.T) *fakeCosmosServer {
	t.Helper()
	// Pre-mint the "next" cert at setup time. require.NoError from inside
	// the HTTP handler would panic ("FailNow from wrong goroutine"); keep
	// all cert-minting on the test goroutine.
	nextCertPEM, nextKeyPEM, nextFP := makeClientCertPEMWithExpiry(t, time.Now().Add(365*24*time.Hour))
	f := &fakeCosmosServer{
		nextCertPEM: nextCertPEM,
		nextKeyPEM:  nextKeyPEM,
		nextFP:      nextFP,
	}

	// ClientAuth=RequestClientCert tells the server to ask for, but not
	// require, a client cert — so the handler can inspect what the
	// renewer actually presented.
	serverCert, _ := makeServerCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requestCount.Add(1)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			f.gotPeerCN.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
		} else {
			f.gotPeerCN.Store("")
		}
		f.gotAPIKey.Store(r.Header.Get(ApoxyAPIKeyHeaderKey))

		if s := f.statusCode.Load(); s != 0 {
			http.Error(w, "forced failure", int(s))
			return
		}

		resp := IssueClientCertResponse{
			Certificate: string(f.nextCertPEM),
			PrivateKey:  string(f.nextKeyPEM),
			CA:          "",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.srv = srv
	return f
}

// hostPort strips the https:// prefix from the test server URL so it slots
// into Options.APIHost (the renewer builds the URL itself).
func (f *fakeCosmosServer) hostPort() string {
	return strings.TrimPrefix(f.srv.URL, "https://")
}

// renewerFixture wraps a CertRenewer plus the inputs callers want to
// inspect after a run (the seed cert, the kube client). Keeping it as a
// struct lets table-driven tests reach into pre-renewal state without
// re-deriving anything.
type renewerFixture struct {
	r          *CertRenewer
	server     *fakeCosmosServer
	seedCert   []byte
	seedKey    []byte
	seedFP     string
}

func newRenewerFixture(t *testing.T, liveNotAfter time.Time) *renewerFixture {
	t.Helper()
	server := newFakeCosmosServer(t)
	certPEM, keyPEM, fp := makeClientCertPEMWithExpiry(t, liveNotAfter)
	bundle, err := bundleFromPEM(certPEM, keyPEM, nil)
	require.NoError(t, err)

	kc := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      apizCertSecretName,
			Namespace: "apoxy",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			tlsSecretCert: certPEM,
			tlsSecretKey:  keyPEM,
			tlsSecretCA:   nil,
		},
	})

	store := newCertStore()
	store.Store(bundle)

	r := &CertRenewer{
		kc:    kc,
		store: store,
		opts: &Options{
			ProjectID:   uuid.New(),
			Namespace:   "apoxy",
			ClusterName: "renew-test",
			APIHost:     server.hostPort(),
			LocalMode:   true, // skip TLS verify against the test server's self-signed cert
		},
	}
	return &renewerFixture{r: r, server: server, seedCert: certPEM, seedKey: keyPEM, seedFP: fp}
}

func TestCertRenewer_CheckAndRenew(t *testing.T) {
	type expect struct {
		httpCalls      int32
		skippedDelta   float64
		successDelta   float64
		failureDelta   float64
		secretChanged  bool
		mTLSAuthUsed   bool // peer cert presented + no API-key header
	}
	cases := []struct {
		name           string
		liveValidity   time.Duration
		threshold      time.Duration
		serverStatus   int // 0 → 200 OK
		expect         expect
	}{
		{
			name:         "healthy cert above threshold skips",
			liveValidity: 60 * 24 * time.Hour,
			threshold:    30 * 24 * time.Hour,
			expect:       expect{skippedDelta: 1},
		},
		{
			name:         "near-expiry cert renews via mTLS",
			liveValidity: 5 * 24 * time.Hour,
			threshold:    30 * 24 * time.Hour,
			expect: expect{
				httpCalls:     1,
				successDelta:  1,
				secretChanged: true,
				mTLSAuthUsed:  true,
			},
		},
		{
			name:         "cosmos error increments failure and leaves Secret intact",
			liveValidity: 5 * 24 * time.Hour,
			threshold:    30 * 24 * time.Hour,
			serverStatus: http.StatusInternalServerError,
			expect: expect{
				httpCalls:    1,
				failureDelta: 1,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newRenewerFixture(t, time.Now().Add(tc.liveValidity))
			if tc.serverStatus != 0 {
				fx.server.statusCode.Store(int32(tc.serverStatus))
			}

			skippedBefore := testutil.ToFloat64(certRenewSkipped)
			successBefore := testutil.ToFloat64(certRenewals.WithLabelValues(resultSuccess))
			failureBefore := testutil.ToFloat64(certRenewals.WithLabelValues(resultFailure))

			fx.r.checkAndRenew(context.Background(), tc.threshold)

			require.Equal(t, tc.expect.httpCalls, fx.server.requestCount.Load(), "unexpected number of cosmos calls")
			require.Equal(t, skippedBefore+tc.expect.skippedDelta, testutil.ToFloat64(certRenewSkipped))
			require.Equal(t, successBefore+tc.expect.successDelta, testutil.ToFloat64(certRenewals.WithLabelValues(resultSuccess)))
			require.Equal(t, failureBefore+tc.expect.failureDelta, testutil.ToFloat64(certRenewals.WithLabelValues(resultFailure)))

			if tc.expect.mTLSAuthUsed {
				require.NotEmpty(t, fx.server.gotPeerCN.Load(), "renewer must present a TLS client cert")
				require.Equal(t, "", fx.server.gotAPIKey.Load(), "renewer must NOT send the bootstrap API key on renewal")
			}

			cur, err := fx.r.kc.CoreV1().Secrets("apoxy").Get(context.Background(), apizCertSecretName, metav1.GetOptions{})
			require.NoError(t, err)
			if tc.expect.secretChanged {
				newBundle, err := bundleFromPEM(cur.Data[tlsSecretCert], cur.Data[tlsSecretKey], cur.Data[tlsSecretCA])
				require.NoError(t, err)
				require.Equal(t, fx.server.nextFP, newBundle.fp, "Secret must hold the cert cosmos returned")
			} else {
				require.Equal(t, fx.seedCert, cur.Data[tlsSecretCert], "Secret tls.crt must be untouched")
			}
		})
	}
}

func TestCertRenewer_StartLifecycle(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
	}{
		{name: "disabled by negative interval returns immediately", interval: -1},
		{name: "running renewer returns on ctx cancel", interval: time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newRenewerFixture(t, time.Now().Add(365*24*time.Hour))
			fx.r.opts.RenewInterval = tc.interval
			fx.r.opts.RenewThreshold = 30 * 24 * time.Hour

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- fx.r.Start(ctx) }()

			if tc.interval >= 0 {
				cancel()
			} else {
				defer cancel()
			}

			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(2 * time.Second):
				t.Fatal("Start did not return")
			}
		})
	}
}
