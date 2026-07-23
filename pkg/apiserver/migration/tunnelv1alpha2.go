// Package migration holds one-shot storage migrations run at apiserver startup.
//
// tunnelv1alpha2 translates legacy core.apoxy.dev/v1alpha2 Tunnel/TunnelAgent
// objects into the vpc.apoxy.dev/v1alpha1 group (VPCNetwork/VPCService). The
// legacy kinds are removed from the scheme in the same change, so their stored
// objects can no longer be read through the typed client; the migration reads
// them straight from the kine backend using frozen private struct copies, then
// writes the replacements through the apiserver and tombstones the old keys.
package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	"github.com/k3s-io/kine/pkg/endpoint"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/client/versioned"
	vpcclient "github.com/apoxy-dev/apoxy/client/versioned/typed/vpc/v1alpha1"
)

// kinePrefix is the storage key prefix kine writes objects under. It matches
// StorageConfig.Prefix in pkg/apiserver/storage.go; the per-resource segment is
// the GroupResource string (resource.String()), NOT a group/resource path.
const kinePrefix = "/kine/"

const (
	legacyTunnelPrefix      = kinePrefix + "tunnels.core.apoxy.dev/"
	legacyTunnelAgentPrefix = kinePrefix + "tunnelagents.core.apoxy.dev/"
)

// kvStore is the backend surface the migration needs: prefix reads and
// single-key tombstones. Delete goes through a transaction because kine does not
// implement the etcd DeleteRange RPC directly (see kineKV.Delete).
type kvStore interface {
	Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
	Delete(ctx context.Context, key string, modRevision int64) error
}

// kineKV adapts a *clientv3.Client to kvStore. kine implements neither the
// standalone DeleteRange RPC nor an unguarded transaction; it only accepts the
// exact optimistic-concurrency shape the apiserver's storage layer uses. A
// tombstone is therefore issued as an If(ModRevision==rev)/Then(Delete)/Else(Get)
// transaction keyed on the revision observed during the read.
type kineKV struct{ cli *clientv3.Client }

func (k kineKV) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return k.cli.Get(ctx, key, opts...)
}

func (k kineKV) Delete(ctx context.Context, key string, modRevision int64) error {
	resp, err := k.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", modRevision)).
		Then(clientv3.OpDelete(key)).
		Else(clientv3.OpGet(key)).
		Commit()
	if err != nil {
		return err
	}
	if !resp.Succeeded {
		return fmt.Errorf("legacy key %q changed during migration", key)
	}
	return nil
}

// frozenTunnel is a minimal, frozen copy of the deleted
// core/v1alpha2.Tunnel storage shape. Only the fields the migration carries
// forward are decoded.
type frozenTunnel struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		EgressGateway *struct {
			Enabled bool `json:"enabled"`
		} `json:"egressGateway"`
	} `json:"spec"`
	Status struct {
		Credentials *struct {
			Token string `json:"token"`
		} `json:"credentials"`
	} `json:"status"`
}

// frozenTunnelAgent is a minimal, frozen copy of the deleted
// core/v1alpha2.TunnelAgent storage shape.
type frozenTunnelAgent struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		TunnelRef struct {
			Name string `json:"name"`
		} `json:"tunnelRef"`
	} `json:"spec"`
}

// tunnelToVPCNetwork maps a legacy Tunnel to its VPCNetwork replacement. The
// overlay CIDR and Ready condition are left for the VPCNetwork provisioner to
// assign on first reconcile; the connect credential is carried separately via
// a status update so the provisioner's mint-once guard skips it.
func tunnelToVPCNetwork(t *frozenTunnel) *vpcv1alpha1.VPCNetwork {
	n := &vpcv1alpha1.VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: t.Metadata.Name}}
	if t.Spec.EgressGateway != nil {
		n.Spec.EgressGateway = &vpcv1alpha1.EgressGatewaySpec{Enabled: t.Spec.EgressGateway.Enabled}
	}
	return n
}

// tunnelAgentToVPCService maps a legacy TunnelAgent to a VPCService selecting
// the Tunnels that reconnecting agents of the same name will produce (the relay
// stamps tunnel.apoxy.dev/name onto each Tunnel's labels). The agent's ephemeral
// connections are not carried forward.
func tunnelAgentToVPCService(a *frozenTunnelAgent) *vpcv1alpha1.VPCService {
	return &vpcv1alpha1.VPCService{
		ObjectMeta: metav1.ObjectMeta{Name: a.Metadata.Name},
		Spec: vpcv1alpha1.VPCServiceSpec{
			NetworkRef: vpcv1alpha1.VPCNetworkRef{Name: a.Spec.TunnelRef.Name},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{vpcv1alpha1.LabelTunnelName: a.Metadata.Name},
			},
		},
	}
}

// Migrate connects to the kine backend and the local apiserver, then runs the
// one-shot legacy-Tunnel migration. It is a no-op once no legacy objects remain,
// so it is safe to run on every startup.
func Migrate(ctx context.Context, etcd endpoint.ETCDConfig, restCfg *rest.Config) error {
	cli, err := newEtcdClient(etcd)
	if err != nil {
		return err
	}
	defer cli.Close()

	cs, err := versioned.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating apoxy client: %w", err)
	}
	return Run(ctx, kineKV{cli: cli}, cs.VpcV1alpha1())
}

// newEtcdClient dials the kine backend. The single-node backend is a plain unix
// socket (no ServerTLSConfig), but honor TLS when a deployment configures it.
func newEtcdClient(etcd endpoint.ETCDConfig) (*clientv3.Client, error) {
	cfg := clientv3.Config{Endpoints: etcd.Endpoints, DialTimeout: 10 * time.Second}
	if etcd.TLSConfig.CertFile != "" {
		tlsInfo := transport.TLSInfo{
			CertFile:      etcd.TLSConfig.CertFile,
			KeyFile:       etcd.TLSConfig.KeyFile,
			TrustedCAFile: etcd.TLSConfig.CAFile,
		}
		tlsCfg, err := tlsInfo.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("building etcd TLS config: %w", err)
		}
		cfg.TLS = tlsCfg
	}
	cli, err := clientv3.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("dialing kine backend: %w", err)
	}
	return cli, nil
}

// Run performs the migration against the given kine KV client (legacy reads +
// tombstones) and vpc client (replacement writes). Each legacy key is deleted
// only after its replacement is durably created, so a completed migration leaves
// an empty legacy prefix and a re-run is a no-op; a partial failure re-migrates
// only the remainder.
func Run(ctx context.Context, kv kvStore, vpc vpcclient.VpcV1alpha1Interface) error {
	if err := migrateTunnels(ctx, kv, vpc); err != nil {
		return err
	}
	return migrateTunnelAgents(ctx, kv, vpc)
}

func migrateTunnels(ctx context.Context, kv kvStore, vpc vpcclient.VpcV1alpha1Interface) error {
	resp, err := kv.Get(ctx, legacyTunnelPrefix, clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("listing legacy Tunnels: %w", err)
	}
	for _, item := range resp.Kvs {
		var t frozenTunnel
		if err := json.Unmarshal(item.Value, &t); err != nil {
			slog.Warn("Skipping unparseable legacy Tunnel", "key", string(item.Key), "error", err)
			continue
		}
		if t.Metadata.Name == "" {
			slog.Warn("Skipping legacy Tunnel with empty name", "key", string(item.Key))
			continue
		}

		net := tunnelToVPCNetwork(&t)
		created, err := vpc.VPCNetworks().Create(ctx, net, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			created, err = vpc.VPCNetworks().Get(ctx, net.Name, metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("creating VPCNetwork %q: %w", net.Name, err)
		}

		// Carry the legacy connect credential so deployed agents keep
		// authenticating, unless the network already has one.
		if t.Status.Credentials != nil && t.Status.Credentials.Token != "" &&
			(created.Status.Credentials == nil || created.Status.Credentials.Token == "") {
			created.Status.Credentials = &vpcv1alpha1.VPCNetworkCredentials{Token: t.Status.Credentials.Token}
			if _, err := vpc.VPCNetworks().UpdateStatus(ctx, created, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("setting VPCNetwork %q credentials: %w", net.Name, err)
			}
		}

		if err := kv.Delete(ctx, string(item.Key), item.ModRevision); err != nil {
			return fmt.Errorf("deleting legacy Tunnel key %q: %w", string(item.Key), err)
		}
		slog.Info("Migrated legacy Tunnel to VPCNetwork", "name", net.Name)
	}
	return nil
}

func migrateTunnelAgents(ctx context.Context, kv kvStore, vpc vpcclient.VpcV1alpha1Interface) error {
	resp, err := kv.Get(ctx, legacyTunnelAgentPrefix, clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("listing legacy TunnelAgents: %w", err)
	}
	for _, item := range resp.Kvs {
		var a frozenTunnelAgent
		if err := json.Unmarshal(item.Value, &a); err != nil {
			slog.Warn("Skipping unparseable legacy TunnelAgent", "key", string(item.Key), "error", err)
			continue
		}
		if a.Metadata.Name == "" || a.Spec.TunnelRef.Name == "" {
			slog.Warn("Skipping legacy TunnelAgent with missing name or tunnelRef", "key", string(item.Key))
			continue
		}

		svc := tunnelAgentToVPCService(&a)
		if _, err := vpc.VPCServices().Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating VPCService %q: %w", svc.Name, err)
		}

		if err := kv.Delete(ctx, string(item.Key), item.ModRevision); err != nil {
			return fmt.Errorf("deleting legacy TunnelAgent key %q: %w", string(item.Key), err)
		}
		slog.Info("Migrated legacy TunnelAgent to VPCService", "name", svc.Name, "network", svc.Spec.NetworkRef.Name)
	}
	return nil
}
