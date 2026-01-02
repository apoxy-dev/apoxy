package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

const ApiServerFinalizer = "apiserver.apoxy.dev/finalizer"

// TunnelNodeReconciler implements a basic garbage collector for dead/orphaned
// TunnelNode objects.
type TunnelNodeReconciler struct {
	client.Client

	jwksHost              string
	jwksPort              int
	tokenRefreshThreshold time.Duration
	ipamv6, ipamv4        tunnet.IPAM

	validator token.Validator
	issuer    token.TokenIssuer
}

func NewTunnelNodeReconciler(
	c client.Client,
	validator token.Validator,
	issuer token.TokenIssuer,
	jwksHost string,
	jwksPort int,
	tokenRefreshThreshold time.Duration,
	ipamv6, ipamv4 tunnet.IPAM,
) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		Client:                c,
		validator:             validator,
		issuer:                issuer,
		jwksHost:              jwksHost,
		jwksPort:              jwksPort,
		tokenRefreshThreshold: tokenRefreshThreshold,
		ipamv6:                ipamv6,
		ipamv4:                ipamv4,
	}
}

func (r *TunnelNodeReconciler) isNewTokenNeeded(
	ctx context.Context,
	credentials *corev1alpha.TunnelNodeCredentials,
	subj string,
) (bool, error) {
	log := controllerlog.FromContext(ctx, "subj", subj)

	if credentials == nil {
		log.Info("Credentials are nil")
		return true, nil
	}

	if credentials.Token == "" {
		log.Info("Token is empty")
		return true, nil
	}

	claims, err := r.validator.Validate(credentials.Token)
	if err != nil { // Not supposed to happen so log the issue
		log.Error(err, "Token validation failed")
		return true, nil
	}

	tokenSubj, err := claims.GetSubject()
	if err != nil {
		log.Error(err, "Failed to get subject from token claims")
		return true, nil
	}

	if tokenSubj != subj {
		log.Info("Token subject does not match", "expected", subj, "got", tokenSubj)
		return true, nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		log.Error(err, "Failed to get expiration time")
		return true, nil
	}

	if exp.Before(time.Now().Add(r.tokenRefreshThreshold)) {
		log.Info("Token is about to expire", "exp", exp, "threshold", r.tokenRefreshThreshold)
		return true, nil
	}

	return false, nil
}

func (r *TunnelNodeReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	tn := &corev1alpha.TunnelNode{}
	if err := r.Get(ctx, req.NamespacedName, tn); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("TunnelNode not found")
		return ctrl.Result{}, nil // Not found
	}

	log.Info("Reconciling TunnelNode")

	if !tn.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("TunnelNode is being deleted")

		for _, agent := range tn.Status.Agents {
			if agent.AgentAddress == "" {
				continue
			}
			addr, err := netip.ParseAddr(agent.AgentAddress)
			if err != nil {
				log.Error(err, "Failed to parse IP address", "addr", agent.AgentAddress)
				continue
			}
			if err := r.ipamv6.Release(netip.PrefixFrom(addr, 96)); err != nil {
				log.Error(err, "Failed to release IP address", "addr", addr)
			}
		}

		controllerutil.RemoveFinalizer(tn, ApiServerFinalizer)
		if err := r.Update(ctx, tn); err != nil {
			return ctrl.Result{}, err
		}
		// TODO(dsky): Wait for all clients to disconnect before deleting (with grace period).
		return ctrl.Result{}, nil // Deleted
	}

	if !controllerutil.ContainsFinalizer(tn, ApiServerFinalizer) {
		log.Info("Adding finalizer to TunnelNode")
		controllerutil.AddFinalizer(tn, ApiServerFinalizer)
		if err := r.Update(ctx, tn); err != nil {
			return ctrl.Result{}, err
		}
	}

	if ok, err := r.isNewTokenNeeded(
		controllerlog.IntoContext(ctx, log),
		tn.Status.Credentials,
		string(tn.ObjectMeta.UID),
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to check if new token is needed: %w", err)
	} else if ok {
		subj, err := uuid.Parse(string(tn.ObjectMeta.UID))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to parse UID as UUID: %w", err)
		}

		token, claims, err := r.issuer.IssueToken(subj.String(), 2*r.tokenRefreshThreshold)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to issue token: %w", err)
		}
		exp, err := claims.GetExpirationTime()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to get expiration from token claims: %w", err)
		}

		log.Info("Issued new token", "subj", subj, "exp", exp)

		tn.Status.Credentials = &corev1alpha.TunnelNodeCredentials{
			Token: token,
		}

		if err := r.Status().Update(ctx, tn); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
		}
	}

	for i, agent := range tn.Status.Agents {
		if agent.AgentAddress != "" {
			log.V(1).Info("Agent already has address", "agent", agent.Name, "addr", agent.AgentAddress)
			continue
		}

		addrv6, err := r.ipamv6.Allocate()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to allocate agent address: %w", err)
		}

		log.Info("Allocated agent v6 address", "agent", agent.Name, "addr", addrv6)

		tn.Status.Agents[i].AgentAddress = addrv6.Addr().String()

		addrv4, err := r.ipamv4.Allocate()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to allocate agent address: %w", err)
		}

		log.Info("Allocated agent v4 address", "agent", agent.Name, "addr", addrv4)

		tn.Status.Agents[i].AgentAddresses = append(tn.Status.Agents[i].AgentAddresses, addrv4.Addr().String())

		if err := r.Status().Update(ctx, tn); err != nil {
			if err := r.ipamv6.Release(addrv6); err != nil {
				log.Error(err, "Failed to release agent address", "agent", agent.Name, "addr", addrv6)
			}
			return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

func (r *TunnelNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		Complete(r)
}

// ServeJWKS starts an HTTP server to serve JWK sets
func (r *TunnelNodeReconciler) ServeJWKS(ctx context.Context) error {
	jwksHandler, err := token.NewJWKSHandler(r.validator.PublicKeyPEM())
	if err != nil {
		return fmt.Errorf("failed to create JWKS handler: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(token.JWKSURI, jwksHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", r.jwksHost, r.jwksPort),
		Handler: mux,
	}

	slog.Info("Starting JWKS HTTP server", slog.String("addr", server.Addr))

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Failed to shutdown JWKS server", slog.Any("error", err))
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("JWKS server failed: %w", err)
	}

	return nil
}
