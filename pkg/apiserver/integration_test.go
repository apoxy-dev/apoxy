package apiserver

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"

	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	a3yclient "github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/auth"
)

type testServer struct {
	addr   string
	cancel context.CancelFunc
	http   *http.Client
}

type observedIdentity struct {
	name   string
	groups []string
}

type authRecorderPlugin struct {
	*admission.Handler

	denyAnonymous bool
	observed      chan observedIdentity
}

var _ admission.ValidationInterface = &authRecorderPlugin{}

func (p *authRecorderPlugin) ValidateInitialization() error {
	return nil
}

func (p *authRecorderPlugin) Validate(_ context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	info := a.GetUserInfo()
	identity := observedIdentity{}
	if info != nil {
		identity.name = info.GetName()
		identity.groups = append(identity.groups, info.GetGroups()...)
	}

	select {
	case p.observed <- identity:
	default:
	}

	if p.denyAnonymous && (info == nil || info.GetName() == kuser.Anonymous) {
		return admission.NewForbidden(a, fmt.Errorf("anonymous user is not allowed"))
	}

	return nil
}

func TestAPIServerIntegrationReadyzAndHealthz(t *testing.T) {
	srv := startTestServer(t)
	t.Cleanup(srv.cancel)

	assertHTTPStatus(t, srv.http, "https://"+srv.addr+"/readyz", http.StatusOK)
	assertHTTPStatus(t, srv.http, "https://"+srv.addr+"/healthz", http.StatusOK)
}

func TestAPIServerIntegrationDomainRecordCRUDAndSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "apiserver.db")
	srv := startTestServer(t, WithSQLitePath(dbPath))
	t.Cleanup(srv.cancel)

	client := newClientset(t, srv.addr)
	records := client.CoreV1alpha3().DomainRecords()

	record := &corev1alpha3.DomainRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "api.example.com--a"},
		Spec: corev1alpha3.DomainRecordSpec{
			Name: "api.example.com",
			TTL:  int32Ptr(60),
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{
					A: []string{"192.0.2.10"},
				},
			},
		},
	}

	created, err := records.Create(context.Background(), record, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, "api.example.com--a", created.Name)

	got, err := records.Get(context.Background(), created.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, int32(60), *got.Spec.TTL)

	list, err := records.List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)

	updated := got.DeepCopy()
	updated.Spec.TTL = int32Ptr(600)
	updated, err = records.Update(context.Background(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Equal(t, int32(600), *updated.Spec.TTL)

	assertSQLiteObjectRow(t, dbPath, created.Name, false, `"ttl":600`)

	srv.cancel()

	restarted := startTestServer(t, WithSQLitePath(dbPath))
	t.Cleanup(restarted.cancel)

	restartedClient := newClientset(t, restarted.addr)
	persisted, err := restartedClient.CoreV1alpha3().DomainRecords().Get(context.Background(), created.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, int32(600), *persisted.Spec.TTL)

	require.NoError(t, restartedClient.CoreV1alpha3().DomainRecords().Delete(context.Background(), created.Name, metav1.DeleteOptions{}))
	_, err = restartedClient.CoreV1alpha3().DomainRecords().Get(context.Background(), created.Name, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err), "expected delete to remove record, got %v", err)

	assertSQLiteObjectRow(t, dbPath, created.Name, true, "")
}

func TestAPIServerIntegrationSimpleAuth(t *testing.T) {
	observed := make(chan observedIdentity, 8)
	pluginFactory := func(io.Reader) (admission.Interface, error) {
		return &authRecorderPlugin{
			Handler:       admission.NewHandler(admission.Create),
			denyAnonymous: true,
			observed:      observed,
		}, nil
	}

	srv := startTestServer(
		t,
		WithSimpleAuth(),
		WithAdmissionPlugin("test-auth-recorder", pluginFactory),
	)
	t.Cleanup(srv.cancel)

	authenticated := newClientset(
		t,
		srv.addr,
		WithTransportWrapper(auth.NewTransportWrapperFunc("integration-user", []string{"integration-group"}, nil)),
	)

	record := &corev1alpha3.DomainRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "auth.example.com--a"},
		Spec: corev1alpha3.DomainRecordSpec{
			Name: "auth.example.com",
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{A: []string{"192.0.2.20"}},
			},
		},
	}

	_, err := authenticated.CoreV1alpha3().DomainRecords().Create(context.Background(), record, metav1.CreateOptions{})
	require.NoError(t, err)
	identity := receiveIdentity(t, observed)
	require.Equal(t, "integration-user", identity.name)
	require.NotEqual(t, kuser.Anonymous, identity.name)

	anonymous := newClientset(t, srv.addr)
	record = &corev1alpha3.DomainRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "anonymous.example.com--a"},
		Spec: corev1alpha3.DomainRecordSpec{
			Name: "anonymous.example.com",
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{A: []string{"192.0.2.21"}},
			},
		},
	}

	_, err = anonymous.CoreV1alpha3().DomainRecords().Create(context.Background(), record, metav1.CreateOptions{})
	require.True(t, apierrors.IsForbidden(err), "expected anonymous create to be rejected by admission, got %v", err)
	identity = receiveIdentity(t, observed)
	require.Equal(t, kuser.Anonymous, identity.name)
	require.Contains(t, identity.groups, kuser.AllUnauthenticated)
}

func TestAPIServerIntegrationDomainRecordDefaultingAndValidation(t *testing.T) {
	srv := startTestServer(t)
	t.Cleanup(srv.cancel)

	records := newClientset(t, srv.addr).CoreV1alpha3().DomainRecords()

	created, err := records.Create(context.Background(), &corev1alpha3.DomainRecord{
		Spec: corev1alpha3.DomainRecordSpec{
			Name: "defaulted.example.com",
			Target: corev1alpha3.DomainRecordTarget{
				DNS: &corev1alpha3.DomainRecordTargetDNS{
					A: []string{"192.0.2.30"},
				},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, "defaulted.example.com--a", created.Name)
	require.NotNil(t, created.Spec.TTL)
	require.Equal(t, int32(300), *created.Spec.TTL)
	require.Equal(t, "A", created.Status.Type)

	invalid := created.DeepCopy()
	invalid.Spec.Name = "renamed.example.com"
	_, err = records.Update(context.Background(), invalid, metav1.UpdateOptions{})
	require.True(t, apierrors.IsInvalid(err), "expected immutable-field update to be invalid, got %v", err)
	require.Contains(t, err.Error(), "field is immutable after creation")
}

func startTestServer(t *testing.T, opts ...Option) *testServer {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	serverOpts, err := defaultOptions(ctx)
	require.NoError(t, err)

	serverOpts.resources = []resource.Object{&corev1alpha3.DomainRecord{}}
	serverOpts.sqlitePath = filepath.Join(t.TempDir(), "apiserver.db")
	serverOpts.bindAddress = "127.0.0.1"
	serverOpts.bindPort = reserveTCPPort(t)

	for _, opt := range opts {
		opt(serverOpts)
	}

	if len(serverOpts.resources) == 0 {
		serverOpts.resources = []resource.Object{&corev1alpha3.DomainRecord{}}
	}

	require.NoError(t, start(ctx, serverOpts))

	addr := net.JoinHostPort(serverOpts.loopbackHost(), fmt.Sprintf("%d", serverOpts.bindPort))
	return &testServer{
		addr:   addr,
		cancel: cancel,
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 5 * time.Second,
		},
	}
}

func newClientset(t *testing.T, addr string, opts ...ClientOption) *a3yclient.Clientset {
	t.Helper()

	clientOpts := []ClientOption{WithClientHost(addr)}
	clientOpts = append(clientOpts, opts...)

	cfg := NewClientConfig(clientOpts...)
	clientset, err := a3yclient.NewForConfig(cfg)
	require.NoError(t, err)
	return clientset
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}

func assertHTTPStatus(t *testing.T, client *http.Client, url string, want int) {
	t.Helper()

	resp, err := client.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, want, resp.StatusCode)
}

func assertSQLiteObjectRow(t *testing.T, dbPath, name string, deleted bool, wantValueSubstring string) {
	t.Helper()

	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()

	const query = `
SELECT
	deleted,
	COALESCE(CAST(value AS TEXT), ''),
	COALESCE(CAST(old_value AS TEXT), '')
FROM kine
WHERE
	COALESCE(CAST(value AS TEXT), '') LIKE ?
	OR COALESCE(CAST(old_value AS TEXT), '') LIKE ?
ORDER BY id DESC
LIMIT 1`

	pattern := fmt.Sprintf("%%%q%%", name)
	var deletedInt int
	var value string
	var oldValue string
	require.NoError(t, db.QueryRow(query, pattern, pattern).Scan(&deletedInt, &value, &oldValue))
	require.Equal(t, deleted, deletedInt == 1)

	if wantValueSubstring != "" {
		require.Contains(t, value, wantValueSubstring)
	}
	if deleted {
		require.True(t, strings.Contains(value, name) || strings.Contains(oldValue, name))
	}
}

func receiveIdentity(t *testing.T, observed <-chan observedIdentity) observedIdentity {
	t.Helper()

	select {
	case identity := <-observed:
		return identity
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for admission plugin to observe user identity")
		return observedIdentity{}
	}
}

func int32Ptr(v int32) *int32 {
	return &v
}
