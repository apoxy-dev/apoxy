package tunnel

import (
	"context"
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/net/lwtunnel"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

const (
	// Default configuration for proxy tunnels
	defaultProxyGeneveDev  = "proxy-gnv0"
	defaultProxyGenevePort = 6082
	defaultProxyGeneveVNI  = 200
	defaultProxyGeneveMTU  = 1400
)

var _ reconcile.Reconciler = &ProxyTunnelReconciler{}

// ProxyTunnelReconciler reconciles Proxy objects and manages L3 Geneve tunnels
// to proxy replicas.
type ProxyTunnelReconciler struct {
	client.Client

	localPrivAddr netip.Addr

	gnv *lwtunnel.Geneve
}

// NewProxyTunnelReconciler creates a new reconciler for managing proxy tunnels.
func NewProxyTunnelReconciler(
	c client.Client,
	localPrivAddr netip.Addr,
) *ProxyTunnelReconciler {
	return &ProxyTunnelReconciler{
		Client: c,

		localPrivAddr: localPrivAddr,

		gnv: lwtunnel.NewGeneve(),
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *ProxyTunnelReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	log.Info("Reconciling Proxy tunnels", "proxy", request.Name)

	proxy := &corev1alpha2.Proxy{}
	if err := r.Get(ctx, request.NamespacedName, proxy); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Proxy not found, cleaning up Geneve interface")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get proxy: %w", err)
	}

	ctx = clog.IntoContext(ctx, log)

	var eps []lwtunnel.Endpoint
	for _, replica := range proxy.Status.Replicas {
		if replica.Address == "" {
			log.Info("Skipping replica with no address", "replica", replica.Name)
			continue
		}

		replicaAddr, err := netip.ParseAddr(replica.Address)
		if err != nil {
			log.Error(err, "Failed to parse replica address",
				"replica", replica.Name, "address", replica.Address)
			continue
		}

		if !replicaAddr.Is6() || !replicaAddr.IsGlobalUnicast() {
			log.Error(fmt.Errorf("invalid address"), "Replica address must be global unicast IPv6",
				"replica", replica.Name, "address", replica.Address)
			continue
		}

		remoteULA, err := tunnet.ULAFromPrefix(ctx, netip.PrefixFrom(replicaAddr, 128))
		if err != nil {
			log.Error(err, "Failed to generate ULA for replica",
				"replica", replica.Name, "address", replicaAddr)
			continue
		}

		if replica.PrivateAddress == "" {
			log.Info("Skipping replica with no private address", "replica", replica.Name)
			continue
		}
		privateAddr, err := netip.ParseAddr(replica.PrivateAddress)
		if err != nil {
			log.Error(err, "Failed to parse private address",
				"replica", replica.Name, "address", replica.PrivateAddress)
			continue
		}
		if !privateAddr.IsGlobalUnicast() {
			log.Error(fmt.Errorf("invalid address"), "Private address must be global unicast",
				"replica", replica.Name, "address", replica.PrivateAddress)
			continue
		}

		eps = append(eps, lwtunnel.Endpoint{
			Dst:    *remoteULA,
			Remote: privateAddr,
		})

		log.Info("Added tunnel for replica",
			"replica", replica.Name, "dst", replicaAddr, "nve", privateAddr)
	}

	if err := r.gnv.SyncEndpoints(ctx, eps); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to sync endpoints: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *ProxyTunnelReconciler) SetupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
) error {
	if err := r.gnv.SetUp(ctx, r.localPrivAddr); err != nil {
		return fmt.Errorf("failed to set up global network view: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Proxy{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(r)
}
