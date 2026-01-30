//go:build linux

package controller

import (
	"context"
	"net/netip"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc"
	"github.com/apoxy-dev/apoxy/pkg/log"
	apoxynet "github.com/apoxy-dev/apoxy/pkg/net"
)

const (
	resolverName = "edgefunc-controller-resolver"
)

// EdgeController manages per-namespace edge runtimes with dynamically-loaded functions.
type EdgeController struct {
	runtimeManager   RuntimeManager
	functionDeployer FunctionDeployer
	functionRouter   FunctionRouter

	// defaultNamespace is used when namespace is not specified.
	defaultNamespace Namespace
}

// EdgeControllerOption configures an EdgeController.
type EdgeControllerOption func(*EdgeController)

// WithDefaultNamespace sets the default namespace for the controller.
func WithDefaultNamespace(ns Namespace) EdgeControllerOption {
	return func(c *EdgeController) {
		c.defaultNamespace = ns
	}
}

// NewEdgeController creates a new EdgeController.
func NewEdgeController(
	runtimeManager RuntimeManager,
	functionDeployer FunctionDeployer,
	functionRouter FunctionRouter,
	opts ...EdgeControllerOption,
) *EdgeController {
	c := &EdgeController{
		runtimeManager:   runtimeManager,
		functionDeployer: functionDeployer,
		functionRouter:   functionRouter,
		defaultNamespace: "default",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewEdgeControllerFromRuntime creates a fully-wired EdgeController from a ContainerRuntime.
func NewEdgeControllerFromRuntime(runtime ContainerRuntime, eszipDir string, defaultNS Namespace) *EdgeController {
	rm := NewRuntimeManager(runtime, WithBaseEszipDir(eszipDir))
	fr := NewFunctionRouter(rm)
	fd := NewFunctionDeployer(rm, fr)
	return NewEdgeController(rm, fd, fr, WithDefaultNamespace(defaultNS))
}

// Deploy deploys an EdgeFunctionRevision to the appropriate namespace runtime.
// If namespace is empty, uses the default namespace.
func (c *EdgeController) Deploy(ctx context.Context, namespace Namespace, rev *extensionsv1alpha2.EdgeFunctionRevision) error {
	if namespace == "" {
		namespace = c.defaultNamespace
	}
	return c.functionDeployer.Deploy(ctx, namespace, rev)
}

// Undeploy removes a function from its runtime.
func (c *EdgeController) Undeploy(ctx context.Context, namespace Namespace, functionID FunctionID) error {
	if namespace == "" {
		namespace = c.defaultNamespace
	}
	return c.functionDeployer.Undeploy(ctx, namespace, functionID)
}

// GetFunctionStatus returns the status of a deployed function.
func (c *EdgeController) GetFunctionStatus(ctx context.Context, namespace Namespace, functionID FunctionID) (*FunctionInfo, error) {
	if namespace == "" {
		namespace = c.defaultNamespace
	}
	return c.functionDeployer.GetFunctionStatus(ctx, namespace, functionID)
}

// GetRuntimeAddress returns the address and port for a namespace's runtime.
func (c *EdgeController) GetRuntimeAddress(ctx context.Context, namespace Namespace) (netip.Addr, int, error) {
	if namespace == "" {
		namespace = c.defaultNamespace
	}
	return c.functionRouter.GetRuntimeAddress(ctx, namespace)
}

// ResolveFunctionID resolves a function name to its active function ID.
func (c *EdgeController) ResolveFunctionID(ctx context.Context, namespace Namespace, functionName string) (FunctionID, error) {
	if namespace == "" {
		namespace = c.defaultNamespace
	}
	return c.functionRouter.Resolve(ctx, namespace, functionName)
}

// TerminateRuntime terminates the runtime for a namespace.
func (c *EdgeController) TerminateRuntime(ctx context.Context, namespace Namespace) error {
	if namespace == "" {
		namespace = c.defaultNamespace
	}
	return c.runtimeManager.TerminateRuntime(ctx, namespace)
}

// ListRuntimes returns all active runtimes.
func (c *EdgeController) ListRuntimes(ctx context.Context) ([]*RuntimeInfo, error) {
	return c.runtimeManager.ListRuntimes(ctx)
}

// RuntimeManager returns the runtime manager (for advanced use cases).
func (c *EdgeController) RuntimeManager() RuntimeManager {
	return c.runtimeManager
}

// FunctionDeployer returns the function deployer (for advanced use cases).
func (c *EdgeController) FunctionDeployer() FunctionDeployer {
	return c.functionDeployer
}

// FunctionRouter returns the function router (for advanced use cases).
func (c *EdgeController) FunctionRouter() FunctionRouter {
	return c.functionRouter
}

// Resolver returns a DNS plugin handler for resolving edge function names.
// This implements the dns.Plugin interface for CoreDNS integration.
func (c *EdgeController) Resolver(next plugin.Handler) plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
		if len(req.Question) == 0 {
			return dns.RcodeSuccess, nil
		}

		qname := req.Question[0].Name
		if !strings.HasSuffix(qname, strings.TrimSuffix(apoxynet.EdgeFuncDomain, ".")+".") {
			log.Debugf("Query name %v does not end with %q", qname, apoxynet.EdgeFuncDomain)
			return plugin.NextOrFailure(resolverName, next, ctx, w, req)
		}

		name := strings.TrimSuffix(qname, apoxynet.EdgeFuncDomain+".")
		name = strings.TrimSuffix(name, ".")
		if name == "" {
			log.Debugf("Empty name from %v", qname)
			return dns.RcodeNameError, nil
		}

		log.Debugf("Resolving edge function %v", name)

		// For now, resolve using the default namespace.
		// In the future, we might want to extract namespace from the DNS name
		// or use some other mechanism.
		namespace := c.defaultNamespace

		// Get the runtime address for this namespace.
		addr, _, err := c.functionRouter.GetRuntimeAddress(ctx, namespace)
		if err != nil {
			log.Debugf("Failed to get runtime address for namespace %s: %v", namespace, err)
			if err == edgefunc.ErrNotFound {
				msg := new(dns.Msg)
				msg.SetRcode(req, dns.RcodeNameError)
				msg.Authoritative = true
				msg.Ns = []dns.RR{new(dns.NS)}
				msg.Answer = []dns.RR{new(dns.A)}
				w.WriteMsg(msg)
				return dns.RcodeNameError, nil
			}
			return dns.RcodeServerFailure, err
		}

		log.Debugf("Resolved function %v to runtime at %v", name, addr)

		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true

		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		}
		rr.A = addr.AsSlice()

		msg.Answer = append(msg.Answer, rr)
		w.WriteMsg(msg)

		return dns.RcodeSuccess, nil
	})
}
