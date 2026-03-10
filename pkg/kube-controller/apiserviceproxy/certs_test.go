package apiserviceproxy

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
)

func TestGenerateServingCertificate(t *testing.T) {
	cert, _, _, caPEM, err := generateServingCertificate("kube-controller", "apoxy")
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))

	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName: "kube-controller.apoxy.svc",
		Roots:   roots,
	})
	require.NoError(t, err)
}

func TestEnsureServingCertificate(t *testing.T) {
	ctx := context.Background()
	clientset := kubernetesfake.NewSimpleClientset()

	p := &APIServiceProxy{
		kC: clientset,
		opts: &Options{
			Namespace:   "apoxy",
			ServiceName: "kube-controller",
		},
	}

	err := p.ensureServingCertificate(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, p.caBundle)
	require.NotEmpty(t, p.servingCert.Certificate)

	secret, err := clientset.CoreV1().Secrets("apoxy").Get(ctx, apiServiceServingSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, secret.Data[tlsSecretCA])

	p2 := &APIServiceProxy{
		kC: clientset,
		opts: &Options{
			Namespace:   "apoxy",
			ServiceName: "kube-controller",
		},
	}
	err = p2.ensureServingCertificate(ctx)
	require.NoError(t, err)
	require.Equal(t, p.caBundle, p2.caBundle)
	require.Equal(t, p.servingCert.Certificate[0], p2.servingCert.Certificate[0])
}
