package apiserver

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy/api/resource"
	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/apiserver/migration"
)

// TestTunnelMigrationIntegration stands up the embedded apiserver over real kine
// and exercises the phase-6 storage migration end-to-end. It also independently
// validates the storage key layout the migration depends on: creating a current
// vpc resource and confirming its kine key is /kine/<resource>.<group>/<name>,
// which is the same formula the migration uses to find legacy keys.
func TestTunnelMigrationIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverOpts, err := defaultOptions(ctx)
	require.NoError(t, err)
	serverOpts.resources = []resource.Object{
		&vpcv1alpha1.VPCNetwork{},
		&vpcv1alpha1.VPCService{},
		&vpcv1alpha1.Relay{},
		&vpcv1alpha1.Tunnel{},
	}
	serverOpts.sqlitePath = filepath.Join(t.TempDir(), "apiserver.db")
	serverOpts.bindAddress = "127.0.0.1"
	serverOpts.bindPort = reserveTCPPort(t)
	require.NoError(t, start(ctx, serverOpts))

	addr := net.JoinHostPort(serverOpts.loopbackHost(), fmt.Sprintf("%d", serverOpts.bindPort))
	cs := newClientset(t, addr)

	kv, err := clientv3.New(clientv3.Config{
		Endpoints:   serverOpts.kineETCD.Endpoints,
		DialTimeout: 10 * time.Second,
	})
	require.NoError(t, err)
	defer kv.Close()

	// (a) Layout-formula check (non-circular): a freshly created VPCNetwork must
	// land at /kine/vpcnetworks.vpc.apoxy.dev/<name>. If this holds, the
	// migration's legacy prefixes (/kine/tunnels.core.apoxy.dev/, etc.) are
	// derived from the same formula and are correct.
	_, err = cs.VpcV1alpha1().VPCNetworks().Create(ctx, &vpcv1alpha1.VPCNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: "layout-probe"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	probe, err := kv.Get(ctx, "/kine/vpcnetworks.vpc.apoxy.dev/", clientv3.WithPrefix())
	require.NoError(t, err)
	var probeKeys []string
	for _, item := range probe.Kvs {
		probeKeys = append(probeKeys, string(item.Key))
	}
	require.Contains(t, probeKeys, "/kine/vpcnetworks.vpc.apoxy.dev/layout-probe",
		"apiserver kine key layout differs from the migration's assumption")

	// (b) Seed legacy objects at the migration's read prefixes and run it.
	_, err = kv.Put(ctx, "/kine/tunnels.core.apoxy.dev/legacy-net",
		`{"metadata":{"name":"legacy-net"},"spec":{"egressGateway":{"enabled":true}},"status":{"credentials":{"token":"legacy-tok"}}}`)
	require.NoError(t, err)
	_, err = kv.Put(ctx, "/kine/tunnelagents.core.apoxy.dev/legacy-agent",
		`{"metadata":{"name":"legacy-agent"},"spec":{"tunnelRef":{"name":"legacy-net"}}}`)
	require.NoError(t, err)

	require.NoError(t, migration.Migrate(ctx, serverOpts.kineETCD, NewClientConfig(WithClientHost(addr))))

	net, err := cs.VpcV1alpha1().VPCNetworks().Get(ctx, "legacy-net", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, net.Spec.EgressGateway)
	require.True(t, net.Spec.EgressGateway.Enabled)
	require.NotNil(t, net.Status.Credentials)
	require.Equal(t, "legacy-tok", net.Status.Credentials.Token)

	svc, err := cs.VpcV1alpha1().VPCServices().Get(ctx, "legacy-agent", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, "legacy-net", svc.Spec.NetworkRef.Name)
	require.Equal(t, "legacy-agent", svc.Spec.Selector.MatchLabels[vpcv1alpha1.LabelTunnelName])

	// Legacy keys are tombstoned once migrated.
	left, err := kv.Get(ctx, "/kine/tunnels.core.apoxy.dev/", clientv3.WithPrefix())
	require.NoError(t, err)
	require.Empty(t, left.Kvs)
}
