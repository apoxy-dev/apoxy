// Package controllers implements Apoxy Control Plane-side controllers.
package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
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

	ipam net.IPAM
}

// NewProxyReconciler returns a new reconcile.Reconciler.
func NewProxyReconciler(
	c client.Client,
	ipam net.IPAM,
) *ProxyReconciler {
	return &ProxyReconciler{
		Client: c,
		ipam:   ipam,
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *ProxyReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	p := &ctrlv1alpha1.Proxy{}
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
		if !controllerutil.ContainsFinalizer(p, ctrlv1alpha1.ProxyFinalizer) {
			log.Info("Adding finalizer to Proxy")
			controllerutil.AddFinalizer(p, ctrlv1alpha1.ProxyFinalizer)
			if err := r.Update(ctx, p); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else { // The object is being deleted
		log.Info("Proxy is being deleted", "phase", p.Status.Phase)

		switch p.Status.Phase {
		case ctrlv1alpha1.ProxyPhaseRunning, ctrlv1alpha1.ProxyPhasePending:
			synced, err := r.syncProxy(ctx, p, true)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to reconcile: %w", err)
			}
			if synced {
				log.Info("Backplane deleted")
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseStopped
				p.Status.Reason = "Proxy deleted"
			} else {
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseTerminating
			}

			if err := r.Status().Update(ctx, p); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		case ctrlv1alpha1.ProxyPhaseTerminating:
			synced, err := r.syncProxy(ctx, p, true)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to reconcile: %w", err)
			}
			if synced {
				log.Info("Backplane deleted")
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseStopped
				p.Status.Reason = "Proxy deleted"
				if err := r.Status().Update(ctx, p); err != nil {
					return ctrl.Result{}, err
				}
			} else if time.Now().After(p.ObjectMeta.DeletionTimestamp.Add(terminationTimeout)) {
				log.Info("Proxy termination timed out. Setting status to stopped and cleaning up")
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseStopped
				p.Status.Reason = fmt.Sprintf("Proxy termination timed out after %s", terminationTimeout)
				if err := r.Status().Update(ctx, p); err != nil {
					return ctrl.Result{}, err
				}
			} else {
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
		case ctrlv1alpha1.ProxyPhaseStopped, ctrlv1alpha1.ProxyPhaseFailed:
			log.Info("Proxy is stopped or failed. Cleaning up")
		default:
			log.Error(nil, "Unknown phase", "app", string(p.UID), "phase", p.Status.Phase)
			return ctrl.Result{}, fmt.Errorf("unknown phase %s", p.Status.Phase)
		}

		switch p.Spec.Provider {
		case ctrlv1alpha1.InfraProviderCloud:
			p.Status.Phase = ctrlv1alpha1.ProxyPhaseFailed
			p.Status.Reason = "Infra provider not implemented"
			if err := r.Status().Update(ctx, p); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		case ctrlv1alpha1.InfraProviderUnmanaged:
			log.Info("Deleting unmanaged Proxy")
		default:
			return ctrl.Result{}, fmt.Errorf("unknown provider: %s", p.Spec.Provider)
		}

		controllerutil.RemoveFinalizer(p, ctrlv1alpha1.ProxyFinalizer)
		if err := r.Update(ctx, p); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil // Deleted.
	}

	switch p.Status.Phase {
	case ctrlv1alpha1.ProxyPhasePending:
		synced, err := r.syncProxy(ctx, p, false /* delete */)
		if err != nil {
			if _, ok := err.(retryableError); ok {
				p.Status.Phase = ctrlv1alpha1.ProxyPhaseFailed
				p.Status.Reason = fmt.Sprintf("Failed to provision cloud proxy: %v", err)
				if err := r.Status().Update(ctx, p); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to update Proxy: %w", err)
				}
				return ctrl.Result{}, nil // Leave the Proxy in the failed state.
			}
			return ctrl.Result{}, fmt.Errorf("failed to reconcile Fly machines: %w", err)
		} else if synced {
			p.Status.Phase = ctrlv1alpha1.ProxyPhaseRunning
			p.Status.Reason = "Proxy is running"
		}

		if err := r.Status().Update(ctx, p); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update Proxy: %w", err)
		} else {
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *ProxyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ctrlv1alpha1.Proxy{}).
		Complete(r)
}

func (r *ProxyReconciler) syncProxy(ctx context.Context, p *ctrlv1alpha1.Proxy, delete bool) (bool, error) {
	log := log.FromContext(ctx)

	if delete {
		// Replicas are doing the termination themselves, we're just waiting for them to stop.
		for _, replica := range p.Status.Replicas {
			if replica.Phase != ctrlv1alpha1.ProxyReplicaPhaseStopped {
				log.V(1).Info("waiting for proxy replica to stop", "name", replica.Name)
				return false, nil
			}

			log.Info("releasing IP address for proxy replica", "address", replica.Address)

			addr, err := netip.ParseAddr(replica.Address)
			if err != nil {
				log.Error(err, "failed to parse IP address", "address", replica.Address)
				continue
			}
			if err := r.ipam.Release(netip.PrefixFrom(addr, 128)); err != nil {
				log.Error(err, "failed to release IP", "address", replica.Address)
				continue
			}
		}
		return true, nil
	}

	for _, replica := range p.Status.Replicas {
		if replica.Address != "" {
			log.V(1).Info("proxy replica already has an address", "address", replica.Address)
			continue
		}

		log.V(1).Info("allocating IP address for proxy replica")

		addr, err := r.ipam.Allocate()
		if err != nil {
			return false, fmt.Errorf("failed to allocate IPv6 address: %w", err)
		}
		if !addr.IsSingleIP() {
			log.Error(err, "allocated IP address is not a single IP", "address", addr.String())
			continue
		}
		replica.Address = addr.Addr().String()

		log.Info("allocated IP address for proxy replica", "address", replica.Address)
	}

	switch p.Spec.Provider {
	case ctrlv1alpha1.InfraProviderUnmanaged:
		// For unmanaged proxies, we set single replica whose name is the same as the proxy.
		if len(p.Status.Replicas) == 0 {
			p.Status.Replicas = append(p.Status.Replicas, &ctrlv1alpha1.ProxyReplicaStatus{
				Name:      p.Name,
				CreatedAt: metav1.Now(),
				Phase:     ctrlv1alpha1.ProxyReplicaPhasePending,
				Reason:    "starting unmanaged proxy",
			})
			return false, nil
		}
		if p.Status.Replicas[0].Phase == ctrlv1alpha1.ProxyReplicaPhaseRunning {
			return true, nil
		}
	default:
		return false, fmt.Errorf("unknown provider: %s", p.Spec.Provider)
	}

	return false, nil
}
