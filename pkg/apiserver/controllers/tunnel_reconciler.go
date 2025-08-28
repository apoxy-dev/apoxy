package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
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

	// handle deletion
	if !tunnel.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&tunnel, ApiServerFinalizer) {
			log.Info("handling Tunnel deletion")

			// Remove finalizer
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				var cur corev1alpha2.Tunnel
				if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
					return getErr
				}
				controllerutil.RemoveFinalizer(&cur, ApiServerFinalizer)
				return r.client.Update(ctx, &cur)
			}); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// ensure finalizer
	if !controllerutil.ContainsFinalizer(&tunnel, ApiServerFinalizer) {
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.Tunnel
			if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
				return getErr
			}
			controllerutil.AddFinalizer(&cur, ApiServerFinalizer)
			return r.client.Update(ctx, &cur)
		}); err != nil {
			return ctrl.Result{}, err
		}
	}

	// ensure bearer token
	if tunnel.Status.Credentials == nil || tunnel.Status.Credentials.Token == "" {
		token, err := generateBearerToken(tokenLength)
		if err != nil {
			return ctrl.Result{}, err
		}

		log.Info("generating new bearer token for Tunnel")

		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.Tunnel
			if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
				return getErr
			}
			if cur.Status.Credentials == nil {
				cur.Status.Credentials = &corev1alpha2.TunnelCredentials{}
			}
			cur.Status.Credentials.Token = token
			return r.client.Status().Update(ctx, &cur)
		}); err != nil {
			return ctrl.Result{}, err
		}
	}

	log.Info("Tunnel reconciled successfully")
	return ctrl.Result{}, nil
}

func (r *TunnelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.Tunnel{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// generateBearerToken creates a random, base64-url-encoded token of n bytes.
func generateBearerToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	// URL-safe base64 without padding
	return base64.RawURLEncoding.EncodeToString(b), nil
}
