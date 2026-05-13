package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy/pkg/cert"
)

// makeTestCertPEM mints a self-signed PEM that ParseCertificate accepts —
// used to verify the fingerprint helper round-trips against the same SHA1
// scheme cosmos uses when persisting issued certs.
func makeTestCertPEM(t *testing.T, notAfter time.Time) ([]byte, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kube-controller-test"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, cert.Fingerprint(der)
}

func TestFingerprintFromCertPEM(t *testing.T) {
	exp := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	pemBytes, wantFP := makeTestCertPEM(t, exp)

	gotFP, gotExp, err := fingerprintFromCertPEM(pemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotFP != wantFP {
		t.Errorf("fingerprint mismatch: got %s want %s", gotFP, wantFP)
	}
	if !gotExp.Equal(exp) {
		t.Errorf("expiry mismatch: got %s want %s", gotExp, exp)
	}
}

func TestFingerprintFromCertPEM_RejectsNonCertBlock(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-cert")})
	if _, _, err := fingerprintFromCertPEM(bad); err == nil {
		t.Fatal("expected error for non-CERTIFICATE PEM block")
	}
}

func TestAssertSafeStrategy(t *testing.T) {
	one := int32(1)
	three := int32(3)
	cases := []struct {
		name            string
		dep             *appsv1.Deployment
		allowDisruption bool
		wantErr         bool
	}{
		{
			name: "single replica default strategy",
			dep: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-controller"},
				Spec:       appsv1.DeploymentSpec{Replicas: &one},
			},
		},
		{
			name: "three replicas without override",
			dep: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-controller"},
				Spec:       appsv1.DeploymentSpec{Replicas: &three},
			},
			wantErr: true,
		},
		{
			name: "three replicas with allow-disruption",
			dep: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-controller"},
				Spec:       appsv1.DeploymentSpec{Replicas: &three},
			},
			allowDisruption: true,
		},
		{
			name: "Recreate strategy refused",
			dep: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-controller"},
				Spec: appsv1.DeploymentSpec{
					Replicas: &one,
					Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
				},
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := assertSafeStrategy(tc.dep, tc.allowDisruption)
			if (err != nil) != tc.wantErr {
				t.Errorf("got err=%v want wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadUserJWT_FlagWins(t *testing.T) {
	t.Setenv("APOXY_USER_JWT", "env-jwt")
	got, err := loadUserJWT("flag-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "flag-jwt" {
		t.Errorf("got %q want flag-jwt", got)
	}
}

func TestLoadUserJWT_EnvFallback(t *testing.T) {
	t.Setenv("APOXY_USER_JWT", "env-jwt")
	got, err := loadUserJWT("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "env-jwt" {
		t.Errorf("got %q want env-jwt", got)
	}
}

