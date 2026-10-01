package identity

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
)

func TestVerify(t *testing.T) {
	oldCA := newTestCA(t, "old")
	newCA := newTestCA(t, "new")
	otherCA := newTestCA(t, "other")
	key := newKey(t)
	issued := testNow.Add(-time.Hour)

	byOld := oldCA.issue(t, &key.PublicKey, testID, issued)
	byNew := newCA.issue(t, &key.PublicKey, testID, issued)
	byOther := otherCA.issue(t, &key.PublicKey, testID, issued)
	clientOnly := oldCA.issue(t, &key.PublicKey, testID, issued, x509.ExtKeyUsageClientAuth)
	twoURIs := oldCA.issue(t, &key.PublicKey, testID, issued)
	twoURIs.URIs = append(twoURIs.URIs, ID{Project: "p", VPC: "v", Agent: "a"}.URI())

	revoked := func(agent string, at time.Time) []vpcv1alpha1.RevokedAgent {
		return []vpcv1alpha1.RevokedAgent{{Name: agent, RevokedAt: metav1.NewTime(at)}}
	}

	cases := []struct {
		name      string
		cert      *x509.Certificate
		bundle    [][]byte
		project   string
		vpc       string
		list      []vpcv1alpha1.RevokedAgent
		now       time.Time
		usages    []x509.ExtKeyUsage
		wantErrIs error
		wantErr   bool
	}{
		{name: "valid", cert: byOld, bundle: [][]byte{oldCA.pem}},
		{name: "wrong project", cert: byOld, bundle: [][]byte{oldCA.pem}, project: "other", wantErrIs: ErrWrongProject},
		{name: "wrong VPC", cert: byOld, bundle: [][]byte{oldCA.pem}, vpc: "other", wantErrIs: ErrWrongVPC},
		{name: "expired", cert: byOld, bundle: [][]byte{oldCA.pem}, now: issued.Add(CertLifetime + time.Second), wantErr: true},
		{name: "not yet valid", cert: byOld, bundle: [][]byte{oldCA.pem}, now: issued.Add(-time.Second), wantErr: true},
		{name: "revoked after issue", cert: byOld, bundle: [][]byte{oldCA.pem}, list: revoked("laptop", issued.Add(time.Minute)), wantErrIs: ErrRevoked},
		{name: "revoked at issue second", cert: byOld, bundle: [][]byte{oldCA.pem}, list: revoked("laptop", issued), wantErrIs: ErrRevoked},
		{name: "issued after revoke", cert: byOld, bundle: [][]byte{oldCA.pem}, list: revoked("laptop", issued.Add(-time.Second))},
		{name: "other agent revoked", cert: byOld, bundle: [][]byte{oldCA.pem}, list: revoked("desktop", issued.Add(time.Minute))},
		{name: "wrong CA", cert: byOther, bundle: [][]byte{oldCA.pem}, wantErr: true},
		{name: "rotation: old cert, two CAs", cert: byOld, bundle: [][]byte{oldCA.pem, newCA.pem}},
		{name: "rotation: new cert, two CAs", cert: byNew, bundle: [][]byte{oldCA.pem, newCA.pem}},
		{name: "rotation: old CA removed", cert: byOld, bundle: [][]byte{newCA.pem}, wantErr: true},
		{name: "server usage", cert: byOld, bundle: [][]byte{oldCA.pem}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "server usage missing", cert: clientOnly, bundle: [][]byte{oldCA.pem}, usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, wantErr: true},
		{name: "two URI SANs", cert: twoURIs, bundle: [][]byte{oldCA.pem}, wantErr: true},
		{name: "no CA bundle", cert: byOld, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := VerifyOptions{
				Project:   testID.Project,
				VPC:       testID.VPC,
				Revoked:   tc.list,
				Now:       testNow,
				KeyUsages: tc.usages,
			}
			if tc.bundle != nil {
				var bundle []byte
				for _, b := range tc.bundle {
					bundle = append(bundle, b...)
				}
				pool, err := NewPool(bundle)
				require.NoError(t, err)
				opts.Roots = pool
			}
			if tc.project != "" {
				opts.Project = tc.project
			}
			if tc.vpc != "" {
				opts.VPC = tc.vpc
			}
			if !tc.now.IsZero() {
				opts.Now = tc.now
			}
			id, err := Verify([]*x509.Certificate{tc.cert}, opts)
			switch {
			case tc.wantErrIs != nil:
				assert.ErrorIs(t, err, tc.wantErrIs)
			case tc.wantErr:
				assert.Error(t, err)
			default:
				require.NoError(t, err)
				assert.Equal(t, testID, id)
			}
		})
	}
}

func TestNewPool(t *testing.T) {
	ca := newTestCA(t, "ca")
	ca2 := newTestCA(t, "ca2")
	key := newKey(t)
	leaf := ca.issue(t, &key.PublicKey, testID, testNow)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	cases := []struct {
		name    string
		in      []byte
		wantErr bool
	}{
		{name: "one CA", in: ca.pem},
		{name: "two CAs", in: append(append([]byte{}, ca.pem...), ca2.pem...)},
		{name: "empty", in: nil, wantErr: true},
		{name: "not a CA", in: certPEM(leaf), wantErr: true},
		{name: "key block", in: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), wantErr: true},
		{name: "bad cert", in: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPool(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
