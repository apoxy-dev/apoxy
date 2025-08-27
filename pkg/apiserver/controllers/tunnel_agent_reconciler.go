package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"

	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

const (
	indexByTunnelRef = "spec.tunnelRef.name"
)

// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnelagents/finalizers,verbs=update
// +kubebuilder:rbac:groups=core.apoxy.dev/v1alpha2,resources=tunnels,verbs=get;list;watch

type TunnelAgentReconciler struct {
	client                client.Client
	agentIPAM             tunnet.IPAM
	validator             *token.InMemoryValidator
	issuer                *token.Issuer
	tokenRefreshThreshold time.Duration
}

// NewTunnelAgentReconciler constructs the reconciler with private fields.
func NewTunnelAgentReconciler(
	c client.Client,
	jwtPrivateKeyPEM []byte,
	jwtPublicKeyPEM []byte,
	tokenRefreshThreshold time.Duration,
	agentIPAM tunnet.IPAM,
) (*TunnelAgentReconciler, error) {
	validator, err := token.NewInMemoryValidator(jwtPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create token validator: %w", err)
	}

	issuer, err := token.NewIssuer(jwtPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create token issuer: %w", err)
	}

	r := &TunnelAgentReconciler{
		client:                c,
		agentIPAM:             agentIPAM,
		validator:             validator,
		issuer:                issuer,
		tokenRefreshThreshold: tokenRefreshThreshold,
	}
	return r, nil
}

func (r *TunnelAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	var agent corev1alpha2.TunnelAgent
	if err := r.client.Get(ctx, req.NamespacedName, &agent); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// handle deletion
	if !agent.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&agent, ApiServerFinalizer) {
			if err := r.releasePrefixIfPresent(&agent, log); err != nil {
				log.Error(err, "failed to release prefix; will retry")
				return ctrl.Result{}, fmt.Errorf("failed to release prefix: %w", err)
			}

			// Remove finalizer
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				var cur corev1alpha2.TunnelAgent
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
	if !controllerutil.ContainsFinalizer(&agent, ApiServerFinalizer) {
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.TunnelAgent
			if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
				return getErr
			}
			controllerutil.AddFinalizer(&cur, ApiServerFinalizer)
			return r.client.Update(ctx, &cur)
		}); err != nil {
			return ctrl.Result{}, err
		}
	}

	// fetch owner Tunnel
	tunnelName := agent.Spec.TunnelRef.Name
	if tunnelName == "" {
		log.Info("tunnelRef.name is empty; skipping")
		return ctrl.Result{}, nil
	}

	var tunnel corev1alpha2.Tunnel
	if err := r.client.Get(ctx, client.ObjectKey{Name: tunnelName}, &tunnel); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Referenced Tunnel not found; will retry", "tunnel", tunnelName)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}

		return ctrl.Result{}, err
	}

	// ensure controller ownerRef agent -> tunnel (retry on conflict)
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cur corev1alpha2.TunnelAgent
		if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
			return getErr
		}
		changed, ensureErr := r.ensureControllerOwner(&cur, &tunnel)
		if ensureErr != nil {
			return ensureErr
		}
		if !changed {
			return nil
		}
		return r.client.Update(ctx, &cur)
	}); err != nil {
		return ctrl.Result{}, err
	}

	// (re)load latest after potential updates above
	if err := r.client.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: req.Namespace}, &agent); err != nil {
		return ctrl.Result{}, err
	}

	// populate status on create / when empty (retry on conflict)
	if agent.Status.Prefix == "" {
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.TunnelAgent
			if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
				return getErr
			}
			if cur.Status.Prefix != "" { // someone else already set it
				return nil
			}

			// allocate on-demand within the retry to avoid leaks
			pfx, ipErr := r.agentIPAM.Allocate()
			if ipErr != nil {
				return fmt.Errorf("failed to allocate prefix: %w", ipErr)
			}
			cur.Status.Prefix = pfx.String()
			if updErr := r.client.Status().Update(ctx, &cur); updErr != nil {
				// release on failed update (including conflicts)
				_ = r.agentIPAM.Release(pfx)
				return updErr
			}
			return nil
		}); err != nil {
			return ctrl.Result{}, err
		}
		// refresh local copy
		if err := r.client.Get(ctx, req.NamespacedName, &agent); err != nil {
			return ctrl.Result{}, err
		}
	}

	subject := agent.Name
	needsToken, exp, err := r.isNewTokenNeeded(
		ctx,
		agent.Status.Credentials,
		subject,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to check if new token is needed: %w", err)
	}

	if needsToken {
		// Issue a token that lasts 2x the refresh threshold.
		// We'll schedule a refresh at T(now + threshold), i.e., half-life.
		ttl := 2 * r.tokenRefreshThreshold
		tokenStr, _, err := r.issuer.IssueToken(subject, ttl)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to issue token: %w", err)
		}

		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			var cur corev1alpha2.TunnelAgent
			if getErr := r.client.Get(ctx, req.NamespacedName, &cur); getErr != nil {
				return getErr
			}
			// re-check on the fresh object to avoid unnecessary writes
			recheckNeeded, _, chkErr := r.isNewTokenNeeded(ctx, cur.Status.Credentials, subject)
			if chkErr != nil {
				return chkErr
			}
			if !recheckNeeded {
				return nil
			}
			if cur.Status.Credentials == nil {
				cur.Status.Credentials = &corev1alpha2.TunnelCredentials{}
			}
			cur.Status.Credentials.Token = tokenStr
			return r.client.Status().Update(ctx, &cur)
		}); err != nil {
			return ctrl.Result{}, err
		}

		// Requeue once at half-life (i.e., threshold from now)
		return ctrl.Result{RequeueAfter: r.withJitter(r.tokenRefreshThreshold)}, nil
	}

	// Token exists and is valid. Schedule a reconcile just before it crosses the refresh threshold.
	if !exp.IsZero() {
		target := exp.Add(-r.tokenRefreshThreshold) // time we want to refresh by
		delay := time.Until(target)
		if delay < 0 {
			delay = 0
		}
		if delay <= 0 {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{RequeueAfter: r.withJitter(delay)}, nil
	}

	return ctrl.Result{}, nil
}

func (r *TunnelAgentReconciler) releasePrefixIfPresent(agent *corev1alpha2.TunnelAgent, log logr.Logger) error {
	if agent.Status.Prefix == "" || r.agentIPAM == nil {
		return nil
	}

	pfx, err := netip.ParsePrefix(agent.Status.Prefix)
	if err != nil {
		log.Error(err, "invalid prefix in status; skipping release", "prefix", agent.Status.Prefix)
		return nil
	}

	return r.agentIPAM.Release(pfx)
}

func (r *TunnelAgentReconciler) ensureControllerOwner(child client.Object, owner client.Object) (bool, error) {
	for _, or := range child.GetOwnerReferences() {
		if or.UID == owner.GetUID() && or.Controller != nil && *or.Controller {
			return false, nil
		}
	}

	// Set controller reference (overwrites any existing controller owner)
	if err := controllerutil.SetControllerReference(
		owner,
		child,
		r.client.Scheme(),
	); err != nil {
		return false, err
	}

	return true, nil
}

func (r *TunnelAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// field index
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1alpha2.TunnelAgent{}, indexByTunnelRef,
		func(obj client.Object) []string {
			ta := obj.(*corev1alpha2.TunnelAgent)
			if ta.Spec.TunnelRef.Name == "" {
				return nil
			}
			return []string{ta.Spec.TunnelRef.Name}
		}); err != nil {
		return fmt.Errorf("index TunnelAgents by TunnelRef: %w", err)
	}

	// map Tunnel -> its agents
	mapTunnelToAgents := handler.TypedEnqueueRequestsFromMapFunc[*corev1alpha2.Tunnel](func(ctx context.Context, t *corev1alpha2.Tunnel) []reconcile.Request {
		var list corev1alpha2.TunnelAgentList
		if err := mgr.GetClient().List(ctx, &list, client.MatchingFields{indexByTunnelRef: t.Name}); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for _, ta := range list.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: ta.Name}})
		}
		return reqs
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha2.TunnelAgent{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WatchesRawSource(
			source.Kind(mgr.GetCache(), &corev1alpha2.Tunnel{}, mapTunnelToAgents),
		).
		Complete(r)
}

// withJitter adds a small +/-10% jitter to avoid thundering herds.
func (r *TunnelAgentReconciler) withJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	j := float64(d) * (0.1 * (rand.Float64()*2 - 1)) // [-10%, +10%]
	return d + time.Duration(j)
}

// isNewTokenNeeded decides if a new token should be issued based on current credentials
// and the configured tokenRefreshThreshold. Returns whether a new token is needed,
// the current token's expiration (if any), and an error.
func (r *TunnelAgentReconciler) isNewTokenNeeded(
	ctx context.Context,
	credentials *corev1alpha2.TunnelCredentials,
	subj string,
) (bool, time.Time, error) {
	log := controllerlog.FromContext(ctx, "subj", subj)

	if credentials == nil {
		log.Info("Credentials are nil")
		return true, time.Time{}, nil
	}

	if credentials.Token == "" {
		log.Info("Token is empty")
		return true, time.Time{}, nil
	}

	claims, err := r.validator.Validate(credentials.Token)
	if err != nil {
		log.Error(err, "Token validation failed")
		return true, time.Time{}, nil
	}

	tokenSubj, err := claims.GetSubject()
	if err != nil {
		log.Error(err, "Failed to get subject from token claims")
		return true, time.Time{}, nil
	}

	if tokenSubj != subj {
		log.Info("Token subject does not match", "expected", subj, "got", tokenSubj)
		return true, time.Time{}, nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		log.Error(err, "Failed to get expiration time")
		return true, time.Time{}, nil
	}

	expTime := exp.Time
	if expTime.Before(time.Now().Add(r.tokenRefreshThreshold)) {
		log.Info("Token is about to expire", "exp", expTime, "threshold", r.tokenRefreshThreshold)
		return true, expTime, nil
	}

	return false, expTime, nil
}
