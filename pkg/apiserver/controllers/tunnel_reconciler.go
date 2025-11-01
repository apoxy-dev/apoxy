package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels/finalizers,verbs=update

const tokenLength = 32 // 32 bytes -> 43 char base64 string

type TunnelReconciler struct {
	client client.Client
}

func NewTunnelReconciler(c client.Client) *TunnelReconciler {
	return &TunnelReconciler{client: c}
}

func (r *TunnelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	var tunnel corev1alpha2.Tunnel
	if err := r.client.Get(ctx, req.NamespacedName, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion.
	if !tunnel.DeletionTimestamp.IsZero() {
		log.Info("Handling deletion of Tunnel")

		if controllerutil.ContainsFinalizer(&tunnel, ApiServerFinalizer) {
			// Manually implement garbage collection of controller-owned TunnelAgents.
			// This is due to us not using the built in gc controller from k8s.io/controller-manager.

			// List controller-owned TunnelAgents by indexed controller owner UID.
			var agents corev1alpha2.TunnelAgentList
			if err := r.client.List(
				ctx,
				&agents,
				client.MatchingFields{".metadata.controllerOwnerUID": string(tunnel.GetUID())},
			); err != nil {
				return ctrl.Result{}, err
			}

			// Kick off deletion for any children that still exist.
			stillPresent := false
			for i := range agents.Items {
				a := &agents.Items[i]
				stillPresent = true
				if a.DeletionTimestamp.IsZero() {
					if err := r.client.Delete(ctx, a); err != nil && !apierrors.IsNotFound(err) {
						return ctrl.Result{}, err
					}
				}
			}

			// If any child remains (possibly terminating due to its own finalizers),
			// requeue and keep the parent's finalizer to emulate foreground deletion.
			if stillPresent {
				log.Info("Waiting for controller-owned TunnelAgents to terminate", "remaining", len(agents.Items))
				return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}

			// No children remain → remove the parent's finalizer.
			log.Info("All controller-owned TunnelAgents gone; removing Tunnel finalizer")

			// Remove finalizer
			controllerutil.RemoveFinalizer(&tunnel, ApiServerFinalizer)
			if err := r.client.Update(ctx, &tunnel); err != nil {
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&tunnel, ApiServerFinalizer) {
		controllerutil.AddFinalizer(&tunnel, ApiServerFinalizer)
		if err := r.client.Update(ctx, &tunnel); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Ensure bearer token in status.
	if tunnel.Status.Credentials == nil || tunnel.Status.Credentials.Token == "" {
		log.Info("Generating new bearer token for Tunnel")

		token, err := generateBearerToken(tokenLength)
		if err != nil {
			return ctrl.Result{}, err
		}

		if tunnel.Status.Credentials == nil {
			tunnel.Status.Credentials = &corev1alpha2.TunnelCredentials{}
		}
		tunnel.Status.Credentials.Token = token

		if err := r.client.Status().Update(ctx, &tunnel); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *TunnelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Tunnel{}, builder.WithPredicates(&predicate.ResourceVersionChangedPredicate{})).
		Complete(r)
}

// generateBearerToken creates a random, base64-url-encoded token of n bytes.
func generateBearerToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
