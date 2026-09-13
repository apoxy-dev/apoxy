package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
)

// errStatusWrite is the error an apiserver connection loss looks like.
var errStatusWrite = errors.New("http2: client connection lost")

// testAgentStatusBackoff makes the same number of attempts as the default
// schedule but without a real wait.
var testAgentStatusBackoff = wait.Backoff{Steps: 5, Duration: time.Millisecond, Factor: 1.0}

// agentStatusScheme builds a scheme that knows the TunnelNode type.
func agentStatusScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1alpha.Install(s))
	return s
}

// statusWriteClient builds a fake cluster client that counts reads and fails
// the first failUpdates status writes. A negative failUpdates fails them all.
// It counts through gets and updates.
func statusWriteClient(
	t *testing.T,
	tn *corev1alpha.TunnelNode,
	present bool,
	failUpdates int,
	gets, updates *atomic.Int32,
) client.Client {
	t.Helper()

	b := fake.NewClientBuilder().WithScheme(agentStatusScheme(t))
	if present {
		b = b.WithObjects(tn).WithStatusSubresource(tn)
	} else {
		b = b.WithStatusSubresource(tn)
	}

	return b.WithInterceptorFuncs(interceptor.Funcs{
		Get: func(
			ctx context.Context,
			c client.WithWatch,
			key client.ObjectKey,
			obj client.Object,
			opts ...client.GetOption,
		) error {
			gets.Add(1)
			return c.Get(ctx, key, obj, opts...)
		},
		SubResourceUpdate: func(
			ctx context.Context,
			c client.Client,
			name string,
			obj client.Object,
			opts ...client.SubResourceUpdateOption,
		) error {
			n := int(updates.Add(1))
			if failUpdates < 0 || n <= failUpdates {
				return errStatusWrite
			}
			return c.Status().Update(ctx, obj, opts...)
		},
	}).Build()
}

// agentNames reads back the agent names in the TunnelNode status.
func agentNames(t *testing.T, c client.Client, name string) []string {
	t.Helper()
	tn := &corev1alpha.TunnelNode{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: name}, tn))
	names := make([]string, 0, len(tn.Status.Agents))
	for _, a := range tn.Status.Agents {
		names = append(names, a.Name)
	}
	return names
}

// TestUpdateAgentStatus pins the retry behaviour of the TunnelNode status
// write: transient errors are retried until the write lands, a write that
// never succeeds reports the error, and a missing TunnelNode stops at once.
func TestUpdateAgentStatus(t *testing.T) {
	const (
		nodeName = "tunnel-node"
		agentID  = "9f3d0c2e-0000-4000-8000-000000000001"
	)

	cases := []struct {
		name string
		// present puts the TunnelNode in the fake cluster.
		present bool
		// failUpdates is the number of status writes that fail first. A
		// negative value fails them all.
		failUpdates int
		wantErr     error
		wantAgent   bool
		wantGets    int32
		wantUpdates int32
	}{
		{
			name:        "a write that succeeds at once registers the agent",
			present:     true,
			wantAgent:   true,
			wantGets:    1,
			wantUpdates: 1,
		},
		{
			name:        "the write is retried until it succeeds",
			present:     true,
			failUpdates: 3,
			wantAgent:   true,
			wantGets:    4,
			wantUpdates: 4,
		},
		{
			name:        "a write that never succeeds reports the error",
			present:     true,
			failUpdates: -1,
			wantErr:     errStatusWrite,
			wantGets:    5,
			wantUpdates: 5,
		},
		{
			name:     "a missing tunnel node is not retried",
			wantErr:  errTunnelNodeNotFound,
			wantGets: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tn := &corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{Name: nodeName, UID: types.UID(uuid.NewString())},
			}
			var gets, updates atomic.Int32
			c := statusWriteClient(t, tn, tc.present, tc.failUpdates, &gets, &updates)

			err := updateAgentStatus(context.Background(), c, testAgentStatusBackoff, nodeName, func(s *corev1alpha.TunnelNodeStatus) {
				upsertAgentStatus(s, &corev1alpha.AgentStatus{
					Name:        agentID,
					ConnectedAt: &metav1.Time{Time: time.Now()},
				})
			})

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantGets, gets.Load(), "tunnel node reads")
			require.Equal(t, tc.wantUpdates, updates.Load(), "tunnel node status writes")

			if tc.present {
				if tc.wantAgent {
					require.Equal(t, []string{agentID}, agentNames(t, c, nodeName))
				} else {
					require.Empty(t, agentNames(t, c, nodeName))
				}
			}
		})
	}
}

// stubQUICConn stands in for the QUIC connection that carries the request.
// The connect handler only closes it.
type stubQUICConn struct {
	quic.Connection
}

func (stubQUICConn) CloseWithError(quic.ApplicationErrorCode, string) error { return nil }

// stubValidator accepts any token and reports a fixed subject.
type stubValidator struct {
	subject string
}

func (v stubValidator) Validate(string) (jwt.Claims, error) {
	return jwt.RegisteredClaims{Subject: v.subject}, nil
}

// connectRequest builds a CONNECT-IP request for the given tunnel. The agent
// process ID and the attempt counter make the server reserve a diversity slot.
func connectRequest(
	t *testing.T,
	ctx context.Context,
	tunUID uuid.UUID,
	agentProcID string,
	attempt int,
) *http.Request {
	t.Helper()

	q := url.Values{}
	q.Set("token", "test-token")
	q.Set("label.version", "test")
	q.Set(metrics.QueryParamAgentProcessID, agentProcID)
	q.Set(QueryParamConnAttempt, strconv.Itoa(attempt))

	u, err := url.Parse("https://proxy/connect/" + tunUID.String() + "?" + q.Encode())
	require.NoError(t, err)

	return (&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-ip",
		URL:    u,
		Host:   "proxy",
		// "?1" is the structured-field boolean true the capsule protocol asks for.
		Header: http.Header{http3.CapsuleProtocolHeader: []string{"?1"}},
	}).WithContext(ctx)
}

// TestConnectRejectsOnAgentStatusFailure pins that a CONNECT-IP request whose
// agent registration does not land is refused, so the agent dials again
// instead of holding a connection that never gets an overlay address.
func TestConnectRejectsOnAgentStatusFailure(t *testing.T) {
	cases := []struct {
		name string
		// present puts the TunnelNode in the fake cluster.
		present     bool
		wantGets    int32
		wantUpdates int32
	}{
		{
			name:        "a status write that never succeeds refuses the connection",
			present:     true,
			wantGets:    5,
			wantUpdates: 5,
		},
		{
			name:     "a missing tunnel node refuses the connection without retries",
			wantGets: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tunUID := uuid.New()
			tn := &corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{Name: "tunnel-node", UID: types.UID(tunUID.String())},
				Status: corev1alpha.TunnelNodeStatus{
					Credentials: &corev1alpha.TunnelNodeCredentials{Token: "test-token"},
				},
			}
			var gets, updates atomic.Int32
			c := statusWriteClient(t, tn, tc.present, -1, &gets, &updates)

			var connected atomic.Bool
			srv, err := NewTunnelServer(
				&SingleClusterClientGetter{Client: c},
				stubValidator{subject: tunUID.String()},
				nil, // The router is not reached on this path.
				WithOnConnect(func(context.Context, string, *corev1alpha.TunnelNode) {
					connected.Store(true)
				}),
			)
			require.NoError(t, err)
			srv.statusBackoff = testAgentStatusBackoff
			srv.tunnels.Set(tunUID.String(), tn)

			handler := srv.makeSingleConnectHandler(context.Background(), stubQUICConn{})
			agentProcID := uuid.NewString()

			before := testutil.ToFloat64(metrics.TunnelConnectionFailures.WithLabelValues("agent_status"))

			// The request context bounds the wait in rejectConnect. It must
			// outlast the retries, which the predicate stops once it is done.
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()

			rec := httptest.NewRecorder()
			handler(rec, connectRequest(t, ctx, tunUID, agentProcID, 0))

			require.Equal(t, http.StatusServiceUnavailable, rec.Code)
			require.False(t, connected.Load(), "the connect callback must not run")
			require.Equal(t, tc.wantGets, gets.Load(), "tunnel node reads")
			require.Equal(t, tc.wantUpdates, updates.Load(), "tunnel node status writes")
			require.Equal(t,
				float64(1),
				testutil.ToFloat64(metrics.TunnelConnectionFailures.WithLabelValues("agent_status"))-before,
				"agent_status failures")

			if tc.present {
				require.Empty(t, agentNames(t, c, tn.Name))
			}

			// The refusal must give the diversity slot back, so the same
			// agent process is admitted again. A slot that is still held
			// answers 409 with the agent_conn_exists reason. This dial only
			// has to pass that check, so a context that is already done
			// keeps the second refusal quick.
			done, cancelDone := context.WithCancel(context.Background())
			cancelDone()

			redial := httptest.NewRecorder()
			handler(redial, connectRequest(t, done, tunUID, agentProcID, 1))

			require.Empty(t, redial.Header().Get(HeaderRejectReason), "the slot must be free")
			require.Equal(t, http.StatusServiceUnavailable, redial.Code)
		})
	}
}
