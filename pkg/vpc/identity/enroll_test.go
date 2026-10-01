package identity

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/client/versioned"
)

// fakeEnrollServer serves vpcnetworks/<vpc>/enroll and /revoke like the
// project apiserver. mutate changes the issued ID to test bad replies.
func fakeEnrollServer(t *testing.T, ca *testCA, mutate func(*ID)) rest.Interface {
	t.Helper()
	const prefix = "/apis/vpc.apoxy.dev/v1alpha1/vpcnetworks/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case prefix + "net1/enroll":
			var req vpcv1alpha1.AgentEnrollment
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			block, _ := pem.Decode([]byte(req.Spec.CSR))
			require.NotNil(t, block)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			require.NoError(t, err)
			require.NoError(t, csr.CheckSignature())
			assert.Empty(t, csr.URIs, "the CSR must carry only the key")
			id := ID{Project: testID.Project, VPC: testID.VPC, Agent: req.Spec.AgentName}
			if mutate != nil {
				mutate(&id)
			}
			cert := ca.issue(t, csr.PublicKey, id, time.Now().Truncate(time.Second))
			req.APIVersion, req.Kind = vpcv1alpha1.SchemeGroupVersion.String(), "AgentEnrollment"
			req.Status = vpcv1alpha1.AgentEnrollmentStatus{
				Certificate: string(certPEM(cert)),
				CABundle:    string(ca.pem),
				ExpiresAt:   metav1.NewTime(cert.NotAfter),
			}
			require.NoError(t, json.NewEncoder(w).Encode(&req))
		case prefix + "net1/revoke":
			var req vpcv1alpha1.AgentRevocation
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			req.APIVersion, req.Kind = vpcv1alpha1.SchemeGroupVersion.String(), "AgentRevocation"
			req.Status.RevokedAt = metav1.NewTime(testNow)
			require.NoError(t, json.NewEncoder(w).Encode(&req))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
		}
	}))
	t.Cleanup(srv.Close)
	cs, err := versioned.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)
	return cs.VpcV1alpha1().RESTClient()
}

func TestEnroll(t *testing.T) {
	ca := newTestCA(t, "ca")
	cases := []struct {
		name    string
		vpc     string
		agent   string
		mutate  func(*ID)
		wantErr bool
	}{
		{name: "valid", vpc: "net1", agent: "laptop"},
		{name: "bad agent name", vpc: "net1", agent: "Laptop", wantErr: true},
		{name: "unknown VPC", vpc: "net2", agent: "laptop", wantErr: true},
		{name: "cert for another agent", vpc: "net1", agent: "laptop", mutate: func(id *ID) { id.Agent = "other" }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fakeEnrollServer(t, ca, tc.mutate)
			cred, err := Enroll(context.Background(), c, tc.vpc, tc.agent)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testID, cred.ID)
			assert.Equal(t, ca.pem, cred.CABundle)
			assert.True(t, cred.Key.PublicKey.Equal(cred.Cert.PublicKey))
		})
	}

	t.Run("new key each time", func(t *testing.T) {
		c := fakeEnrollServer(t, ca, nil)
		a, err := Enroll(context.Background(), c, "net1", "laptop")
		require.NoError(t, err)
		b, err := Enroll(context.Background(), c, "net1", "laptop")
		require.NoError(t, err)
		assert.False(t, a.Key.Equal(b.Key))
	})
}

func TestRevoke(t *testing.T) {
	c := fakeEnrollServer(t, newTestCA(t, "ca"), nil)
	got, err := Revoke(context.Background(), c, "net1", "laptop")
	require.NoError(t, err)
	assert.Equal(t, "laptop", got.Spec.AgentName)
	assert.True(t, got.Status.RevokedAt.Time.Equal(testNow))
}
