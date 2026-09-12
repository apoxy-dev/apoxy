// Package controllers implements Apoxy Control Plane-side controllers.
package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	xdstypes "github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// ProxyReconciler reconciles a Proxy object.
type ProxyReconciler struct {
	client.Client

	resources *message.ProviderResources
	ipam      net.IPAM
	shutdown  func()
}

// NewProxyReconciler returns a new reconcile.Reconciler.
func NewProxyReconciler(
	ctx context.Context,
	c client.Client,
	resources *message.ProviderResources,
	ipam net.IPAM,
	shutdown func(),
) *ProxyReconciler {
	return &ProxyReconciler{
		Client: c,

		resources: resources,
		ipam:      ipam,
		shutdown:  shutdown,
	}
}

// getReplicaAddress returns the address of the given type from a replica, or empty string if not found.
func getReplicaAddress(replica *corev1alpha2.ProxyReplicaStatus, addrType corev1alpha2.ReplicaAddressType) string {
	for _, addr := range replica.Addresses {
		if addr.Type == addrType {
			return addr.Address
		}
	}
	return ""
}

// setReplicaAddress sets or updates an address of the given type on a replica.
func setReplicaAddress(replica *corev1alpha2.ProxyReplicaStatus, addrType corev1alpha2.ReplicaAddressType, address string) {
	for i, addr := range replica.Addresses {
		if addr.Type == addrType {
			replica.Addresses[i].Address = address
			return
		}
	}
	replica.Addresses = append(replica.Addresses, corev1alpha2.ReplicaAddress{
		Type:    addrType,
		Address: address,
	})
}

// nodeMetadataToAddresses converts NodeMetadata addresses to ReplicaAddress slice.
func nodeMetadataToAddresses(meta *xdstypes.NodeMetadata) []corev1alpha2.ReplicaAddress {
	var addrs []corev1alpha2.ReplicaAddress
	if meta.ExternalAddress != "" {
		addrs = append(addrs, corev1alpha2.ReplicaAddress{
			Type:    corev1alpha2.ReplicaExternalIP,
			Address: meta.ExternalAddress,
		})
	}
	if meta.InternalAddress != "" {
		addrs = append(addrs, corev1alpha2.ReplicaAddress{
			Type:    corev1alpha2.ReplicaInternalIP,
			Address: meta.InternalAddress,
		})
	}
	return addrs
}

// envoyExitFromNode converts the Envoy exit record of a node to the API type.
func envoyExitFromNode(exit *xdstypes.NodeEnvoyExit) *corev1alpha2.EnvoyExit {
	if exit == nil {
		return nil
	}
	return &corev1alpha2.EnvoyExit{
		Time:   exit.At,
		Reason: exit.Reason,
		Code:   exit.Code,
	}
}

// sameEnvoyExit reports whether both records describe the same Envoy exit.
func sameEnvoyExit(a, b *corev1alpha2.EnvoyExit) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Time.Equal(&b.Time) && a.Reason == b.Reason && a.Code == b.Code
}

// replicaFromNodeMetadata builds the status of a replica from node metadata.
func replicaFromNodeMetadata(meta *xdstypes.NodeMetadata) *corev1alpha2.ProxyReplicaStatus {
	replica := &corev1alpha2.ProxyReplicaStatus{
		Name:        meta.Name,
		ConnectedAt: meta.ConnectedAt,
		Addresses:   nodeMetadataToAddresses(meta),
	}
	applyNodeMetadata(replica, meta)
	return replica
}

// applyNodeMetadata copies the Envoy restart count and the last exit of a node
// into the status of a replica. It returns true when a field changes.
func applyNodeMetadata(replica *corev1alpha2.ProxyReplicaStatus, meta *xdstypes.NodeMetadata) bool {
	changed := false

	if replica.EnvoyRestarts != meta.EnvoyRestarts {
		replica.EnvoyRestarts = meta.EnvoyRestarts
		changed = true
	}

	exit := envoyExitFromNode(meta.LastEnvoyExit)
	if !sameEnvoyExit(replica.LastEnvoyExit, exit) {
		replica.LastEnvoyExit = exit
		changed = true
	}

	return changed
}

// findReplica returns the status of the named replica of a Proxy, or nil.
func findReplica(p *corev1alpha2.Proxy, name string) *corev1alpha2.ProxyReplicaStatus {
	for _, replica := range p.Status.Replicas {
		if replica.Name == name {
			return replica
		}
	}
	return nil
}

// newestNode returns the node that connected last. The node with more Envoy
// restarts wins when both connected at the same time.
func newestNode(a, b *xdstypes.NodeMetadata) *xdstypes.NodeMetadata {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.ConnectedAt.After(a.ConnectedAt.Time) {
		return b
	}
	if a.ConnectedAt.Equal(&b.ConnectedAt) && b.EnvoyRestarts > a.EnvoyRestarts {
		return b
	}
	return a
}

// nodesByReplica keeps one node per replica name. Every Envoy run gets a new
// node ID, so while Envoy restarts the cache holds the node of the previous run
// next to the node of the new one until the old stream closes.
func nodesByReplica(nodes []*xdstypes.NodeMetadata) map[string]*xdstypes.NodeMetadata {
	byName := make(map[string]*xdstypes.NodeMetadata, len(nodes))
	for _, meta := range nodes {
		byName[meta.Name] = newestNode(byName[meta.Name], meta)
	}
	return byName
}

// liveNode returns the node that still serves a replica of a Proxy, or nil.
// The node of the closed stream is left out by its node ID.
func (r *ProxyReconciler) liveNode(proxyName, replicaName, closedNodeID string) *xdstypes.NodeMetadata {
	var live *xdstypes.NodeMetadata
	for nk, meta := range r.resources.EnvoyResources.Nodes.LoadAll() {
		if nk.ClusterName != proxyName || nk.NodeID == closedNodeID || meta.Name != replicaName {
			continue
		}
		live = newestNode(live, meta)
	}
	return live
}

// applyNodeUpdate applies one xDS node update to the status of a Proxy. It
// returns true when the status changes.
func (r *ProxyReconciler) applyNodeUpdate(
	p *corev1alpha2.Proxy,
	nodeID string,
	meta *xdstypes.NodeMetadata,
	deleted bool,
) bool {
	if !deleted {
		// Update the replica when it is known already, otherwise append it.
		if replica := findReplica(p, meta.Name); replica != nil {
			return applyNodeMetadata(replica, meta)
		}
		p.Status.Replicas = append(p.Status.Replicas, replicaFromNodeMetadata(meta))
		return true
	}

	// The stream of the previous Envoy run closes after the new run connects,
	// so keep the replica while another node of that replica is connected.
	if live := r.liveNode(p.Name, meta.Name, nodeID); live != nil {
		if replica := findReplica(p, live.Name); replica != nil {
			return applyNodeMetadata(replica, live)
		}
		p.Status.Replicas = append(p.Status.Replicas, replicaFromNodeMetadata(live))
		return true
	}

	for i, replica := range p.Status.Replicas {
		if replica.Name == meta.Name {
			p.Status.Replicas = append(p.Status.Replicas[:i], p.Status.Replicas[i+1:]...)
			return true
		}
	}

	return false
}

func (r *ProxyReconciler) releaseReplica(ctx context.Context, replica *corev1alpha2.ProxyReplicaStatus) error {
	log := log.FromContext(ctx)

	ulaAddr := getReplicaAddress(replica, corev1alpha2.ReplicaInternalULA)
	if ulaAddr == "" {
		return nil
	}

	log.Info("Releasing IP address for proxy replica", "address", ulaAddr)

	addr, err := netip.ParseAddr(ulaAddr)
	if err != nil {
		log.Error(err, "Failed to parse IP address", "address", ulaAddr)
		return err
	}

	if err := r.ipam.Release(netip.PrefixFrom(addr, 128)); err != nil {
		log.Error(err, "Failed to release IP", "address", ulaAddr)
		return err
	}

	return nil
}

func (r *ProxyReconciler) assignReplica(ctx context.Context, replica *corev1alpha2.ProxyReplicaStatus) error {
	log := log.FromContext(ctx)

	log.V(1).Info("Allocating IP address for proxy replica")

	addr, err := r.ipam.Allocate()
	if err != nil {
		log.Error(err, "Failed to allocate IPv6 address")
		return err
	}

	if !addr.IsSingleIP() {
		log.Error(err, "Allocated IP address is not a single IP", "address", addr.String())
		return err
	}

	setReplicaAddress(replica, corev1alpha2.ReplicaInternalULA, addr.Addr().String())

	log.Info("Allocated IP address for proxy replica", "address", addr.Addr().String())

	return nil
}

func (r *ProxyReconciler) reconcileRequest(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	p := &corev1alpha2.Proxy{}
	err := r.Get(ctx, request.NamespacedName, p)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get Proxy: %w", err)
	}

	log := log.FromContext(ctx, "name", p.Name)
	log.Info("Reconciling Proxy")

	if p.ObjectMeta.DeletionTimestamp.IsZero() { // Not being deleted, so ensure finalizer is present.
		if !controllerutil.ContainsFinalizer(p, corev1alpha2.ProxyFinalizer) {
			log.Info("Adding finalizer to Proxy")
			controllerutil.AddFinalizer(p, corev1alpha2.ProxyFinalizer)
			if err := r.Update(ctx, p); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else { // The object is being deleted
		log.Info("Proxy is being deleted")

		for _, replica := range p.Status.Replicas {
			if err := r.releaseReplica(ctx, replica); err != nil {
				return ctrl.Result{}, err
			}
		}

		controllerutil.RemoveFinalizer(p, corev1alpha2.ProxyFinalizer)
		if err := r.Update(ctx, p); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil // Deleted.
	}

	for _, replica := range p.Status.Replicas {
		if ulaAddr := getReplicaAddress(replica, corev1alpha2.ReplicaInternalULA); ulaAddr != "" {
			log.V(1).Info("Proxy replica already has a ULA address", "address", ulaAddr)
			continue
		}

		log.Info("Allocating IP address for proxy replica", "replica", replica.Name)

		if err := r.assignReplica(ctx, replica); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := r.Status().Update(ctx, p); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Proxy status: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *ProxyReconciler) run(ctx context.Context) {
	ch := r.resources.EnvoyResources.Nodes.Subscribe(ctx)
	defer r.shutdown() // Call shutdown hook if this loop exits.
	for {
		select {
		case <-ctx.Done():
			slog.Info("Context done", "error", ctx.Err())
			return

		case snapshot, ok := <-ch:
			if !ok {
				slog.Info("Node subscription closed")
				return
			}

			slog.Info("Received xDS nodes snapshot")

			for _, update := range snapshot.Updates {
				proxyName, meta := update.Key.ClusterName, update.Value

				slog.Info("Received update", "proxy", update.Key.ClusterName, "nodeID", update.Key.NodeID)

				p := &corev1alpha2.Proxy{}
				if err := r.Get(ctx, types.NamespacedName{Name: proxyName}, p); err != nil {
					slog.Error("Failed to get proxy", "proxy", proxyName, "error", err)
					continue
				}

				if r.applyNodeUpdate(p, update.Key.NodeID, meta, update.Delete) {
					if err := r.Status().Update(ctx, p); err != nil {
						slog.Error("Failed to update proxy status", "proxy", proxyName, "error", err)
					}
				}
			}

		case <-time.After(1 * time.Minute):
			r.resyncReplicas(ctx)
		}
	}
}

// resyncReplicas matches the replicas in the status of every Proxy against the
// xDS nodes that are connected now. Proxies without connected nodes are also
// visited, so their stale replicas are removed too.
func (r *ProxyReconciler) resyncReplicas(ctx context.Context) {
	slog.Info("Resyncing connected proxy replicas")

	// Maps proxies to their connected nodes from the current state.
	nodeMap := make(map[string][]*xdstypes.NodeMetadata)
	for nk, meta := range r.resources.EnvoyResources.Nodes.LoadAll() {
		nodeMap[nk.ClusterName] = append(nodeMap[nk.ClusterName], meta)
	}

	proxies := &corev1alpha2.ProxyList{}
	if err := r.List(ctx, proxies); err != nil {
		slog.Error("Failed to list proxies", "error", err)
		return
	}

	for i := range proxies.Items {
		p := &proxies.Items[i]
		byName := nodesByReplica(nodeMap[p.Name])

		slog.Info("Proxy has connected replicas", "proxy", p.Name, "replicas", len(byName))

		updated := false
		for _, name := range slices.Sorted(maps.Keys(byName)) {
			meta := byName[name]
			if replica := findReplica(p, name); replica != nil {
				if applyNodeMetadata(replica, meta) {
					updated = true
				}
				continue
			}
			p.Status.Replicas = append(p.Status.Replicas, replicaFromNodeMetadata(meta))
			updated = true
		}

		// Remove replicas that are no longer connected.
		keep := 0
		for _, replica := range p.Status.Replicas {
			if _, ok := byName[replica.Name]; ok {
				p.Status.Replicas[keep] = replica
				keep++
			} else {
				slog.Info("Removing disconnected replica", "proxy", p.Name, "replica", replica.Name)
				updated = true
			}
		}
		p.Status.Replicas = p.Status.Replicas[:keep]

		if updated {
			if err := r.Status().Update(ctx, p); err != nil {
				slog.Error("Failed to update proxy status", "proxy", p.Name, "error", err)
			}
		}
	}
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *ProxyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	go r.run(ctx)
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Proxy{}).
		Complete(reconcile.Func(r.reconcileRequest))
}
