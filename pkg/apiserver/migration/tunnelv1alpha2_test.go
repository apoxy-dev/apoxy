package migration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	versionedfake "github.com/apoxy-dev/apoxy/client/versioned/fake"
	vpcclient "github.com/apoxy-dev/apoxy/client/versioned/typed/vpc/v1alpha1"
)

// fakeKV is an in-memory kvStore. Get treats its key argument as a prefix (the
// only way the migration calls it); Delete removes an exact key.
type fakeKV struct {
	data map[string][]byte
}

func newFakeKV() *fakeKV { return &fakeKV{data: map[string][]byte{}} }

func (f *fakeKV) put(key string, obj any) {
	b, _ := json.Marshal(obj)
	f.data[key] = b
}

func (f *fakeKV) Get(_ context.Context, key string, _ ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	resp := &clientv3.GetResponse{}
	for k, v := range f.data {
		if strings.HasPrefix(k, key) {
			resp.Kvs = append(resp.Kvs, &mvccpb.KeyValue{Key: []byte(k), Value: v})
		}
	}
	return resp, nil
}

func (f *fakeKV) Delete(_ context.Context, key string, _ int64) error {
	delete(f.data, key)
	return nil
}

func newVPCClient() vpcclient.VpcV1alpha1Interface {
	return versionedfake.NewSimpleClientset().VpcV1alpha1()
}

func TestTunnelToVPCNetwork(t *testing.T) {
	cases := []struct {
		name        string
		in          *frozenTunnel
		wantEgress  *bool
		wantNetName string
	}{
		{
			name:        "no egress",
			in:          &frozenTunnel{},
			wantNetName: "",
		},
		{
			name: "egress enabled carried",
			in: func() *frozenTunnel {
				t := &frozenTunnel{}
				t.Metadata.Name = "net-a"
				t.Spec.EgressGateway = &struct {
					Enabled bool `json:"enabled"`
				}{Enabled: true}
				return t
			}(),
			wantEgress:  ptr(true),
			wantNetName: "net-a",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnelToVPCNetwork(tc.in)
			require.Equal(t, tc.wantNetName, got.Name)
			if tc.wantEgress == nil {
				require.Nil(t, got.Spec.EgressGateway)
			} else {
				require.NotNil(t, got.Spec.EgressGateway)
				require.Equal(t, *tc.wantEgress, got.Spec.EgressGateway.Enabled)
			}
			// Migration never assigns identity/credential inline.
			require.Empty(t, got.Status.OverlayCIDR)
			require.Nil(t, got.Status.Credentials)
		})
	}
}

func TestTunnelAgentToVPCService(t *testing.T) {
	a := &frozenTunnelAgent{}
	a.Metadata.Name = "agent-a"
	a.Spec.TunnelRef.Name = "net-a"

	got := tunnelAgentToVPCService(a)
	require.Equal(t, "agent-a", got.Name)
	require.Equal(t, "net-a", got.Spec.NetworkRef.Name)
	require.NotNil(t, got.Spec.Selector)
	require.Equal(t, map[string]string{vpcv1alpha1.LabelTunnelName: "agent-a"}, got.Spec.Selector.MatchLabels)
}

func TestRun(t *testing.T) {
	ctx := context.Background()

	newTunnel := func(name, token string, egress bool) any {
		m := map[string]any{
			"metadata": map[string]any{"name": name},
			"spec":     map[string]any{"egressGateway": map[string]any{"enabled": egress}},
			"status":   map[string]any{"credentials": map[string]any{"token": token}},
		}
		return m
	}
	newAgent := func(name, tunnel string) any {
		return map[string]any{
			"metadata": map[string]any{"name": name},
			"spec":     map[string]any{"tunnelRef": map[string]any{"name": tunnel}},
		}
	}

	t.Run("empty is a no-op", func(t *testing.T) {
		kv := newFakeKV()
		vpc := newVPCClient()
		require.NoError(t, Run(ctx, kv, vpc))
		nets, err := vpc.VPCNetworks().List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.Empty(t, nets.Items)
	})

	t.Run("migrates tunnels and agents, tombstones legacy keys", func(t *testing.T) {
		kv := newFakeKV()
		kv.put(legacyTunnelPrefix+"net-a", newTunnel("net-a", "tok-a", true))
		kv.put(legacyTunnelAgentPrefix+"agent-a", newAgent("agent-a", "net-a"))
		vpc := newVPCClient()

		require.NoError(t, Run(ctx, kv, vpc))

		net, err := vpc.VPCNetworks().Get(ctx, "net-a", metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, net.Spec.EgressGateway)
		require.True(t, net.Spec.EgressGateway.Enabled)
		require.NotNil(t, net.Status.Credentials)
		require.Equal(t, "tok-a", net.Status.Credentials.Token)

		svc, err := vpc.VPCServices().Get(ctx, "agent-a", metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, "net-a", svc.Spec.NetworkRef.Name)
		require.Equal(t, "agent-a", svc.Spec.Selector.MatchLabels[vpcv1alpha1.LabelTunnelName])

		// Legacy keys are tombstoned.
		require.Empty(t, kv.data)
	})

	t.Run("re-run is idempotent", func(t *testing.T) {
		kv := newFakeKV()
		kv.put(legacyTunnelPrefix+"net-a", newTunnel("net-a", "tok-a", false))
		vpc := newVPCClient()

		require.NoError(t, Run(ctx, kv, vpc))
		// Second run sees an empty legacy prefix -> no error, no duplicate.
		require.NoError(t, Run(ctx, kv, vpc))

		_, err := vpc.VPCNetworks().Get(ctx, "net-a", metav1.GetOptions{})
		require.NoError(t, err)
		require.False(t, apierrors.IsNotFound(err))
	})

	t.Run("skips malformed entries", func(t *testing.T) {
		kv := newFakeKV()
		kv.data[legacyTunnelPrefix+"bad"] = []byte("{not json")
		kv.put(legacyTunnelPrefix+"noname", map[string]any{"spec": map[string]any{}})
		vpc := newVPCClient()

		require.NoError(t, Run(ctx, kv, vpc))
		nets, err := vpc.VPCNetworks().List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.Empty(t, nets.Items)
		// Malformed keys are left in place (not tombstoned).
		require.Len(t, kv.data, 2)
	})
}

func ptr[T any](v T) *T { return &v }
