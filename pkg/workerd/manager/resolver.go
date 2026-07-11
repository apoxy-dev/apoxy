// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// errRevisionNotFound distinguishes "the dispatcher asked for an id we have no
// ServiceRevision for" (a 404 to the dispatcher) from a transient pull/build
// failure (a 502). Wrapped, so callers use errors.Is.
var errRevisionNotFound = errors.New("workerd-manager: service revision not found")

// BundleFetcher pulls a bundle from an OCI registry. It is the registry seam:
// the resident reconciler and control server are fake-testable without a live
// registry.
type BundleFetcher interface {
	// Bundle returns the bundle's BundleManifest (the OCI config blob) and
	// each module's bytes keyed by cleaned in-layer path
	// (host.CleanModulePath), matching BundleManifest.Modules[i].Path.
	// Ref resolution and pull credentials both come from the BundleRef.
	Bundle(ctx context.Context, b computev1alpha1.BundleRef) (computev1alpha1.BundleManifest, map[string][]byte, error)
}

// ociBundleFetcher is the production fetcher over the host package's oras-go
// helpers.
type ociBundleFetcher struct{}

func (ociBundleFetcher) Bundle(ctx context.Context, b computev1alpha1.BundleRef) (computev1alpha1.BundleManifest, map[string][]byte, error) {
	return host.FetchBundle(ctx, b)
}

// Resolver turns a dispatcher demux id ("<service>:<revision>") into the
// host.WorkerDefinition the WorkerLoader callback consumes: it loads the
// ServiceRevision, pulls its bundle, and reconstructs the WorkerCode payload.
//
// The resident is per-tenant — a Resolver's kube client is scoped to the single
// project its resident serves — so the id carries no project qualifier; the
// service name alone keys the WorkerLoader cache within this resident.
//
// The client is swappable (setClient): the per-tenant client is handed in on
// every ReconcileWithClient call, and a re-engaged project may arrive with a
// fresh client while the tenant's warm state (and this Resolver, reachable
// from the control server's pull path) lives on.
type Resolver struct {
	mu      sync.RWMutex
	c       client.Client
	fetcher BundleFetcher
}

// NewResolver returns a Resolver over the production OCI fetcher. The client
// must be scoped to the single project the resident serves.
func NewResolver(c client.Client) *Resolver {
	return &Resolver{c: c, fetcher: ociBundleFetcher{}}
}

// newResolverWithFetcher injects a fetcher for tests.
func newResolverWithFetcher(c client.Client, f BundleFetcher) *Resolver {
	return &Resolver{c: c, fetcher: f}
}

// setClient rebinds the project client. Safe against concurrent Resolves from
// the control server's pull path.
func (r *Resolver) setClient(c client.Client) {
	r.mu.Lock()
	r.c = c
	r.mu.Unlock()
}

// getClient returns the current project client.
func (r *Resolver) getClient() client.Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.c
}

// Resolve builds the WorkerDefinition for a demux id. A missing ServiceRevision
// is reported as errRevisionNotFound (wrapped) so the control server can answer
// 404; pull/build failures propagate as-is (a 502 the dispatcher surfaces).
func (r *Resolver) Resolve(ctx context.Context, id string) (host.WorkerDefinition, error) {
	service, revision, err := splitServiceID(id)
	if err != nil {
		return host.WorkerDefinition{}, err
	}

	rev := &computev1alpha1.ServiceRevision{}
	if err := r.getClient().Get(ctx, client.ObjectKey{Name: revision}, rev); err != nil {
		if apierrors.IsNotFound(err) {
			return host.WorkerDefinition{}, fmt.Errorf("%w: %q", errRevisionNotFound, revision)
		}
		return host.WorkerDefinition{}, fmt.Errorf("getting service revision %q: %w", revision, err)
	}
	// Defense in depth: the backplane derives the demux key from the live
	// Service->revision mapping, so the service prefix must match the revision's
	// owning Service. A mismatch is a routing bug, not a 404.
	if got := rev.Labels[serviceLabel]; got != service {
		return host.WorkerDefinition{}, fmt.Errorf("revision %q is owned by service %q, not %q", revision, got, service)
	}

	manifest, modulesByPath, err := r.fetcher.Bundle(ctx, rev.Spec.Bundle)
	if err != nil {
		return host.WorkerDefinition{}, fmt.Errorf("fetching bundle: %w", err)
	}

	// Map each manifest module's in-layer path to its bytes, keyed by Name (the
	// shape BuildWorkerDefinition consumes). A path with no extracted bytes is
	// left absent so BuildWorkerDefinition reports it precisely.
	source := make(map[string][]byte, len(manifest.Modules))
	for _, m := range manifest.Modules {
		if b, ok := modulesByPath[host.CleanModulePath(m.Path)]; ok {
			source[m.Name] = b
		}
	}
	secrets, err := r.resolveSecrets(ctx, service, rev.Spec.ServiceConfigSpec)
	if err != nil {
		return host.WorkerDefinition{}, err
	}
	return host.BuildWorkerDefinition(manifest, rev.Spec.ServiceConfigSpec, source, secrets)
}

// resolveSecrets fetches the values for the revision's secret bindings from
// their SecretStores, re-checking scopes at materialization time (admission
// checked at write time, but stores change independently of revisions).
// Everything is read through the values subresource — a single live,
// cache-bypassing GET per store that the apiserver only serves to internal
// identities and that echoes the parent's scopes — so rotated values and
// scope changes are picked up on the next worker load, nothing is cached
// here, and no informer is ever started on SecretStore (whose cloud storage
// serves no watch).
func (r *Resolver) resolveSecrets(ctx context.Context, service string, cfg computev1alpha1.ServiceConfigSpec) (map[string]string, error) {
	var out map[string]string
	values := make(map[string]*corev1alpha.SecretStoreValues)
	for i := range cfg.Bindings {
		b := &cfg.Bindings[i]
		if b.Type != computev1alpha1.SecretBindingType || b.Secret == nil {
			// Unsupported binding types are reported by BuildWorkerDefinition.
			continue
		}
		name := string(b.Secret.Store)
		vals, ok := values[name]
		if !ok {
			vals = &corev1alpha.SecretStoreValues{}
			parent := &corev1alpha.SecretStore{ObjectMeta: metav1.ObjectMeta{Name: name}}
			if err := r.getClient().SubResource("values").Get(ctx, parent, vals); err != nil {
				return nil, fmt.Errorf("reading values of secret store %q for binding %q: %w", name, b.Name, err)
			}
			if !corev1alpha.ScopesAllow(vals.Scopes, "compute", service) {
				return nil, fmt.Errorf("secret store %q scopes %v do not admit compute service %q (binding %q)",
					name, vals.Scopes, service, b.Name)
			}
			values[name] = vals
		}
		value, ok := vals.Data[b.Secret.Key]
		if !ok {
			return nil, fmt.Errorf("secret store %q has no key %q (binding %q)", name, b.Secret.Key, b.Name)
		}
		if out == nil {
			out = make(map[string]string)
		}
		out[b.Name] = value
	}
	return out, nil
}

// splitServiceID parses the dispatcher demux id "<service>:<revision>". Both are
// DNS-1123 names (no colon), so a well-formed id has exactly one ":". A stale
// three-part "<project>:<service>:<revision>" id (e.g. an old dispatcher hitting
// a new manager mid-rollout) is rejected here rather than mis-parsed — clearer
// than splitting it into a colon-bearing revision name that then 404s.
func splitServiceID(id string) (service, revision string, err error) {
	parts := strings.Split(id, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("workerd-manager: invalid service id %q (want %q)", id, "<service>:<revision>")
	}
	return parts[0], parts[1], nil
}

// serviceRevisionID is the demux id for a ServiceRevision: "<service>:<name>".
// The service comes from the serviceLabel the minting reconciler sets. The
// resident is per-tenant, so the service name alone keys the isolate cache.
func serviceRevisionID(rev *computev1alpha1.ServiceRevision) (string, error) {
	service := rev.Labels[serviceLabel]
	if service == "" {
		return "", fmt.Errorf("workerd-manager: revision %q has no %s label", rev.Name, serviceLabel)
	}
	return service + ":" + rev.Name, nil
}

// demuxID is the dispatcher demux id for a (service, revision) pair:
// "<service>:<revision>". It is the string-arg twin of serviceRevisionID (which
// reads the service off a revision's label) — the publish path knows the service
// name directly. The demux map itself is keyed on the bare service name (the
// resolve key the dispatcher sends), which is this id minus the ":<revision>".
func demuxID(service, revName string) string {
	return service + ":" + revName
}
