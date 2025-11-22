// Package controllers implements Apoxy Control Plane-side controllers.
package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/gateway/message"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

const (
	terminationTimeout = 15 * time.Minute
)

type retryableError struct {
	error
}

var _ reconcile.Reconciler = &ProxyReconciler{}

// ProxyReconciler reconciles a Proxy object.
type ProxyReconciler struct {
	client.Client

	resources *message.ProviderResources
	ipam      net.IPAM
}

// NewProxyReconciler returns a new reconcile.Reconciler.
func NewProxyReconciler(
	ctx context.Context,
	c client.Client,
	resources *message.ProviderResources,
	ipam net.IPAM,
) *ProxyReconciler {
	go func() {
		ch := resources.EnvoyResources.Nodes.Subscribe(ctx)
		for snapshot := range ch {
			slog.Info("Received xDS nodes snapshot")

			for _, update := range snapshot.Updates {
				proxyName, meta := update.Key.ClusterName, update.Value

				slog.Info("Received update", "proxy", update.Key.ClusterName, "nodeID", update.Key.NodeID)

				p := &corev1alpha2.Proxy{}
				if err := c.Get(ctx, types.NamespacedName{Name: proxyName}, p); err != nil {
					slog.Error("failed to get proxy", "proxy", proxyName, "error", err)
					continue
				}

				if !update.Delete {
					p.Status.Replicas = append(p.Status.Replicas, &corev1alpha2.ProxyReplicaStatus{
						Name:           meta.Name,
						ConnectedAt:    metav1.Now(),
						PrivateAddress: meta.PrivateAddress,
					})
				} else {
					for i, replica := range p.Status.Replicas {
						if replica.Name == meta.Name {
							p.Status.Replicas = append(p.Status.Replicas[:i], p.Status.Replicas[i+1:]...)
							break
						}
					}
				}

				if err := c.Status().Update(ctx, p); err != nil {
					slog.Error("failed to update proxy status", "proxy", proxyName, "error", err)
				}
			}
		}
		slog.Info("Node subscription closed")
	}()
	return &ProxyReconciler{
		Client:    c,
		resources: resources,
		ipam:      ipam,
	}
}

func (r *ProxyReconciler) releaseReplica(ctx context.Context, replica *corev1alpha2.ProxyReplicaStatus) error {
	log := log.FromContext(ctx)

	log.Info("releasing IP address for proxy replica", "address", replica.Address)

	addr, err := netip.ParseAddr(replica.Address)
	if err != nil {
		log.Error(err, "failed to parse IP address", "address", replica.Address)
		return err
	}

	if err := r.ipam.Release(netip.PrefixFrom(addr, 128)); err != nil {
		log.Error(err, "failed to release IP", "address", replica.Address)
		return err
	}

	return nil
}

func (r *ProxyReconciler) assignReplica(ctx context.Context, replica *corev1alpha2.ProxyReplicaStatus) error {
	log := log.FromContext(ctx)

	log.V(1).Info("allocating IP address for proxy replica")

	addr, err := r.ipam.Allocate()
	if err != nil {
		log.Error(err, "failed to allocate IPv6 address")
		return err
	}

	if !addr.IsSingleIP() {
		log.Error(err, "allocated IP address is not a single IP", "address", addr.String())
		return err
	}

	replica.Address = addr.Addr().String()

	log.Info("Allocated IP address for proxy replica", "address", replica.Address)

	return nil
}

// Reconcile implements reconcile.Reconciler.
func (r *ProxyReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
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
		if replica.Address != "" {
			log.V(1).Info("proxy replica already has an address", "address", replica.Address)
			continue
		}

		log.Info("allocating IP address for proxy replica")

		if err := r.assignReplica(ctx, replica); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := r.Status().Update(ctx, p); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Proxy status: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *ProxyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Proxy{}).
		Complete(r)
}
