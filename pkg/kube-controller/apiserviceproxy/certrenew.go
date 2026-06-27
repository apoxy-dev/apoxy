package apiserviceproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	"github.com/apoxy-dev/apoxy/pkg/cert/reload"
)

// CertRenewer auto-renews the upstream client cert by re-calling cosmos's
// IssueServiceCert endpoint over mTLS with the current live cert. The
// renewer writes the new Secret; the fsnotify watcher (reload.Watch) then
// picks up the new files and swaps the live transport in place.
//
// CertRenewer implements sigs.k8s.io/controller-runtime/pkg/manager.Runnable
// so it can be added to a leader-elected manager. Wrapping the loop in a
// manager Runnable means a future multi-replica kube-controller will issue
// against cosmos from one pod per tick, not all of them.
type CertRenewer struct {
	kc        kubernetes.Interface
	store     *reload.Store
	opts      *Options
	recorder  record.EventRecorder
	deployRef *corev1.ObjectReference
}

// NewCertRenewer wires a renewer onto an already-configured APIServiceProxy.
// The proxy must have been constructed via NewAPIServiceProxy with cloud
// options (project ID + token) so its certStore is seeded.
//
// recorder may be nil; in that case Kubernetes Events are skipped (metrics
// + slog still cover the failure surface). deployRef points at the kube-
// controller Deployment so `kubectl describe deploy kube-controller`
// surfaces renewal Events.
func NewCertRenewer(
	apiSvc *APIServiceProxy,
	recorder record.EventRecorder,
	deployRef *corev1.ObjectReference,
) *CertRenewer {
	return &CertRenewer{
		kc:        apiSvc.kC,
		store:     apiSvc.certStore,
		opts:      apiSvc.opts,
		recorder:  recorder,
		deployRef: deployRef,
	}
}

// Start runs the renewer until ctx is cancelled. Implements
// sigs.k8s.io/controller-runtime/pkg/manager.Runnable.
//
// The first check happens immediately at startup so a pod that comes up
// with a near-expiry cert renews on boot rather than waiting up to a full
// interval.
func (r *CertRenewer) Start(ctx context.Context) error {
	interval, threshold, enabled := r.resolveCadence()
	if !enabled {
		slog.Info("Cert auto-renewal disabled by configuration")
		return nil
	}
	if r.store == nil {
		slog.Info("Cert auto-renewal disabled: no cert store (cloud mode not configured)")
		return nil
	}

	slog.Info("Starting cert auto-renewer",
		"interval", interval.String(),
		"threshold", threshold.String(),
	)
	r.checkAndRenew(ctx, threshold)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.checkAndRenew(ctx, threshold)
		}
	}
}

// NeedLeaderElection signals controller-runtime to gate Start on leadership.
// Returning true means only the elected pod runs the renewer — the fsnotify
// watcher stays per-pod since each pod's in-process transport must be
// refreshed.
func (r *CertRenewer) NeedLeaderElection() bool { return true }

func (r *CertRenewer) resolveCadence() (time.Duration, time.Duration, bool) {
	interval := r.opts.RenewInterval
	if interval < 0 {
		return 0, 0, false
	}
	if interval == 0 {
		interval = DefaultRenewInterval
	}
	threshold := r.opts.RenewThreshold
	if threshold == 0 {
		threshold = DefaultRenewThreshold
	}
	return interval, threshold, true
}

func (r *CertRenewer) checkAndRenew(ctx context.Context, threshold time.Duration) {
	cur := r.store.Load()
	if cur == nil {
		// Nothing to renew against — bootstrap path must succeed before
		// the renewer can do anything useful.
		return
	}
	remaining := time.Until(cur.NotAfter)
	if remaining > threshold {
		certRenewSkipped.Inc()
		return
	}

	slog.Info("Renewing upstream cert",
		"remaining", remaining.String(),
		"fingerprint", cur.Fingerprint,
	)
	next, err := r.issueWithCert(ctx, cur)
	if err != nil {
		certRenewals.WithLabelValues(resultFailure).Inc()
		slog.Warn("Cert auto-renewal failed",
			"err", err,
			"fingerprint", cur.Fingerprint,
			"remaining", remaining.String(),
		)
		r.recordEvent(corev1.EventTypeWarning, EventReasonCertRenewalFailed,
			fmt.Sprintf("Failed to renew apiz-cert: %v", err))
		return
	}

	certRenewals.WithLabelValues(resultSuccess).Inc()
	slog.Info("Renewed upstream cert",
		"fingerprint", next.Fingerprint,
		"not_after", next.NotAfter.UTC().Format(time.RFC3339),
	)
	r.recordEvent(corev1.EventTypeNormal, EventReasonCertRenewed,
		fmt.Sprintf("Renewed apiz-cert; fingerprint=%s, expires=%s",
			next.Fingerprint, next.NotAfter.UTC().Format(time.RFC3339)))
}

// issueWithCert calls IssueServiceCert authenticated by mTLS with the
// current live cert. The bootstrap-token API key path (used at first
// install) is deliberately not used here — once the controller has a live
// cert, the API key should never be reached for re-issuance.
//
// The request goes to the apiz host (apiz.apoxy.dev / apiz.apoxy.localhost
// in dev), NOT the public api host. apiz is the only virtual host that
// requests the client cert during TLS handshake and forwards it to cosmos's
// ext_authz for service-account cert validation; api does not request a
// client cert, so the cert would never be sent and ext_authz would 403
// the request as unauthenticated.
func (r *CertRenewer) issueWithCert(ctx context.Context, live *reload.Bundle) (*reload.Bundle, error) {
	transport := buildTransport(live, r.opts.LocalMode)
	defer transport.CloseIdleConnections()
	return doIssueCertificate(ctx, &http.Client{Transport: transport}, resolveBaseAPIProxyHost(r.opts.APIHost), map[string]string{
		// Content-Type tells the apiz HTTPProxy to route this to cosmos:8080
		// (the JSON / gRPC-gateway port) rather than cosmos:2020 (raw gRPC).
		"Content-Type":          "application/json",
		ApoxyProjectIdHeaderKey: r.opts.ProjectID.String(),
		ApoxyServiceUserKey:     kubeControllerUserPrefix + r.opts.ClusterName,
	}, r.kc, r.opts.Namespace)
}

func (r *CertRenewer) recordEvent(eventType, reason, message string) {
	if r.recorder == nil || r.deployRef == nil {
		return
	}
	r.recorder.Event(r.deployRef, eventType, reason, message)
}
