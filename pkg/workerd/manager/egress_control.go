// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerdv1 "github.com/apoxy-dev/apoxy/api/workerd/v1"
	"github.com/apoxy-dev/apoxy/pkg/net/dns/vpcdns"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

// EgressControlServer is the manager side of the egress config plane
// (APO-723): a per-tenant gRPC server the backplane's ServiceReconciler
// (APO-726) pushes compiled egress config through. It fans each apply out to
// the resident's EgressController live setters via host.EgressApplier.
//
// Unlike the dispatcher control channel (ControlServer, which the SANDBOX
// reaches through the Sentry's control forwarder and therefore must be
// loopback TCP), this listener is dialed host-side only — so it is a unix
// domain socket, and filesystem permissions on the socket directory are the
// auth boundary. One server serves exactly one tenant: a request naming any
// sandbox other than that tenant's resident is rejected, so a reconciler can
// never push config across projects.
type EgressControlServer struct {
	workerdv1.UnimplementedEgressConfigServer
	workerdv1.UnimplementedDNSConfigServer

	tenant  string
	applier host.EgressApplier
	// dnsApplier is the resident's VPC name-plane sink; nil when the resident
	// implementation doesn't support it, in which case ApplyDNS is rejected
	// (the DNSConfig service shares this socket/server with EgressConfig).
	dnsApplier host.DNSApplier

	path string
	ln   net.Listener
	srv  *grpc.Server
}

// NewEgressControlServer returns an egress control server for tenant, fanning
// applies out through applier (the tenant's resident). dnsApplier (usually
// the same resident) receives DNSConfig pushes; nil disables that service's
// applies.
func NewEgressControlServer(tenant string, applier host.EgressApplier, dnsApplier host.DNSApplier) *EgressControlServer {
	return &EgressControlServer{tenant: tenant, applier: applier, dnsApplier: dnsApplier}
}

// EgressSocketPath is the deterministic per-tenant egress control socket
// under dir — deterministic so the backplane reconciler needs no discovery,
// keyed by the resident sandbox id so tenants can never collide.
func EgressSocketPath(dir, tenant string) string {
	return filepath.Join(dir, string(names.ResidentID(tenant))+".sock")
}

// Listen binds the unix domain socket at path. A stale socket file from a
// previous incarnation is removed first — the manager is the only legitimate
// binder of the path, so an existing file is always leftover, never live
// contention worth preserving.
func (s *EgressControlServer) Listen(path string) error {
	if s.ln != nil {
		return fmt.Errorf("egress control server is already listening on %s", s.path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing stale egress control socket %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listening on egress control socket %s: %w", path, err)
	}
	// The socket directory's 0700 is the auth boundary; tighten the socket
	// file itself too so a loosened directory doesn't expose the plane.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("restricting egress control socket %s: %w", path, err)
	}
	s.path = path
	s.ln = ln
	return nil
}

// Serve serves the egress control API on the listener bound by Listen until
// ctx is cancelled.
func (s *EgressControlServer) Serve(ctx context.Context) error {
	if s.ln == nil {
		return fmt.Errorf("egress control server has no listener; call Listen first")
	}

	s.srv = grpc.NewServer()
	workerdv1.RegisterEgressConfigServer(s.srv, s)
	workerdv1.RegisterDNSConfigServer(s.srv, s)
	// Stop (not GracefulStop) on cancel, mirroring the control channel: an
	// in-flight apply during teardown must not wedge shutdown; the reconciler
	// retries.
	stop := context.AfterFunc(ctx, func() { s.srv.Stop() })
	defer stop()

	slog.Info("Serving workerd egress control channel", "tenant", s.tenant, "path", s.path)
	if err := s.srv.Serve(s.ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serving egress control channel: %w", err)
	}
	return nil
}

// Close releases the bound listener for a server whose Serve was never
// started (an assembly-failure path); Serve's own shutdown (grpc Server.Stop)
// closes it otherwise. Idempotent — a re-run teardown must be a no-op, and in
// particular must never touch the socket path again: the deterministic path
// may already belong to a rebuilt successor server. Socket-file cleanup needs
// no explicit remove — *net.UnixListener unlinks its file on close, and
// Listen reaps a leftover from a killed process.
func (s *EgressControlServer) Close() error {
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	s.ln = nil
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

// ApplyEgress implements workerdv1.EgressConfigServer.
func (s *EgressControlServer) ApplyEgress(ctx context.Context, req *workerdv1.ApplyEgressRequest) (*workerdv1.ApplyEgressResponse, error) {
	if want := string(names.ResidentID(s.tenant)); req.SandboxId != want {
		return nil, status.Errorf(codes.PermissionDenied,
			"sandbox %q is not this tenant's resident", req.SandboxId)
	}

	gen, err := s.applier.ApplyEgress(applyFromProto(req))
	switch {
	case errors.Is(err, sandbox.ErrNotFound):
		// The resident isn't up (yet, or anymore): retryable, the next
		// reconcile re-pushes once it is.
		return nil, status.Errorf(codes.Unavailable, "resident is not running: %v", err)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "applying egress config: %v", err)
	}
	return &workerdv1.ApplyEgressResponse{AppliedGeneration: gen}, nil
}

// ApplyDNS implements workerdv1.DNSConfigServer.
func (s *EgressControlServer) ApplyDNS(ctx context.Context, req *workerdv1.ApplyDNSRequest) (*workerdv1.ApplyDNSResponse, error) {
	if want := string(names.ResidentID(s.tenant)); req.SandboxId != want {
		return nil, status.Errorf(codes.PermissionDenied,
			"sandbox %q is not this tenant's resident", req.SandboxId)
	}
	if s.dnsApplier == nil {
		return nil, status.Error(codes.Unimplemented, "resident does not support DNS control")
	}

	apply, err := dnsApplyFromProto(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid DNS binding: %v", err)
	}

	gen, err := s.dnsApplier.ApplyDNS(apply)
	switch {
	case errors.Is(err, sandbox.ErrNotFound):
		// The resident isn't up (yet, or anymore): retryable, the next
		// reconcile re-pushes once it is.
		return nil, status.Errorf(codes.Unavailable, "resident is not running: %v", err)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "applying DNS config: %v", err)
	}
	return &workerdv1.ApplyDNSResponse{AppliedGeneration: gen}, nil
}

// dnsApplyFromProto maps the wire request to the host apply shape, validating
// addresses and prefixes: a malformed binding is a pusher bug and is rejected
// whole-request (InvalidArgument) rather than silently dropped — partial
// applies would leave the name plane inconsistent with what the pusher
// believes it pushed.
func dnsApplyFromProto(req *workerdv1.ApplyDNSRequest) (host.DNSApply, error) {
	apply := host.DNSApply{
		Zones:      req.AuthoritativeZones,
		Generation: req.Generation,
	}
	for _, b := range req.Bindings {
		binding := vpcdns.Binding{
			FQDN:     b.Fqdn,
			Delegate: b.DelegateSubdomains,
			TTL:      b.Ttl,
		}
		for _, a := range b.Addrs {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return host.DNSApply{}, fmt.Errorf("binding %q addr %q: %w", b.Fqdn, a, err)
			}
			binding.Addrs = append(binding.Addrs, addr)
		}
		for _, c := range b.ReachableCidrs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return host.DNSApply{}, fmt.Errorf("binding %q reachable cidr %q: %w", b.Fqdn, c, err)
			}
			p = p.Masked()
			// A reachable window is a per-endpoint SSRF carve-out. Enforce at
			// this trust boundary that it lies inside the Apoxy overlay ULA:
			// the resident must never be handed a carve-out for loopback,
			// link-local, or arbitrary space even if a buggy/compromised pusher
			// sends one. This is the authoritative check; the bridge's deny()
			// gates on the same prefix as defense in depth.
			if !tunnet.ULAPrefix().Contains(p.Addr()) {
				return host.DNSApply{}, fmt.Errorf("binding %q reachable cidr %q is outside the Apoxy overlay %s", b.Fqdn, c, tunnet.ULAPrefix())
			}
			binding.Reachable = append(binding.Reachable, p)
		}
		apply.Bindings = append(apply.Bindings, binding)
	}
	return apply, nil
}

// applyFromProto maps the wire request to the host apply shape.
func applyFromProto(req *workerdv1.ApplyEgressRequest) host.EgressApply {
	apply := host.EgressApply{
		InvocationID: req.InvocationId,
		Generation:   req.Generation,
	}
	if len(req.Services) > 0 {
		apply.Services = make([]sandbox.ServiceEgress, 0, len(req.Services))
		for _, s := range req.Services {
			apply.Services = append(apply.Services, serviceEgressFromProto(s))
		}
	}
	return apply
}

// serviceEgressFromProto maps one wire per-Service plane to the seam shape.
func serviceEgressFromProto(s *workerdv1.ServiceEgressConfig) sandbox.ServiceEgress {
	se := sandbox.ServiceEgress{Service: s.Service}
	if len(s.Backends) > 0 {
		se.Backends = make([]sandbox.BackendListener, 0, len(s.Backends))
		for _, b := range s.Backends {
			se.Backends = append(se.Backends, sandbox.BackendListener{
				Name:      b.Name,
				Addr:      b.Addr,
				Shape:     b.Shape,
				MatchPort: b.MatchPort,
				Priority:  int(b.Priority),
			})
		}
	}
	if s.Policy != nil {
		p := &sandbox.Policy{DefaultDeny: s.Policy.DefaultDeny}
		for _, r := range s.Policy.Rules {
			rule := sandbox.Rule{
				DestinationCIDRs:     r.DestinationCidrs,
				DestinationHostnames: r.DestinationHostnames,
				Protocol:             r.Protocol,
				Listeners:            r.Listeners,
			}
			for _, pr := range r.Ports {
				rule.Ports = append(rule.Ports, sandbox.PortRange{Start: pr.Start, End: pr.End})
			}
			p.Rules = append(p.Rules, rule)
		}
		se.Policy = p
	}
	return se
}
