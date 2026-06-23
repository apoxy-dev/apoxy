// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

// errRevisionNotFound distinguishes "the dispatcher asked for an id we have no
// ServiceRevision for" (a 404 to the dispatcher) from a transient pull/build
// failure (a 502). Wrapped, so callers use errors.Is.
var errRevisionNotFound = errors.New("workerd-manager: service revision not found")

// BundleFetcher pulls a bundle's manifest and module bytes from an OCI ref. It
// is the registry seam: the resident reconciler and control server are
// fake-testable without a live registry.
type BundleFetcher interface {
	// Manifest returns the bundle's BundleManifest (the OCI config blob).
	Manifest(ctx context.Context, imageRef string) (computev1alpha1.BundleManifest, error)
	// Modules returns each module's bytes keyed by cleaned in-layer path
	// (host.CleanModulePath), matching BundleManifest.Modules[i].Path.
	Modules(ctx context.Context, imageRef string) (map[string][]byte, error)
}

// ociBundleFetcher is the production fetcher over the host package's oras-go
// helpers (anonymous pull, M1).
type ociBundleFetcher struct{}

func (ociBundleFetcher) Manifest(ctx context.Context, imageRef string) (computev1alpha1.BundleManifest, error) {
	return host.FetchBundleManifest(ctx, imageRef)
}

func (ociBundleFetcher) Modules(ctx context.Context, imageRef string) (map[string][]byte, error) {
	return host.FetchBundleModules(ctx, imageRef)
}

// Resolver turns a dispatcher demux id ("<service>:<revision>") into the
// host.WorkerDefinition the WorkerLoader callback consumes: it loads the
// ServiceRevision, pulls its bundle, and reconstructs the WorkerCode payload.
//
// The resident is per-tenant — the manager's kube client is already scoped to
// the single project it serves — so the id carries no project qualifier; the
// service name alone keys the WorkerLoader cache within this resident.
type Resolver struct {
	client.Client
	fetcher BundleFetcher
}

// NewResolver returns a Resolver over the production OCI fetcher. The client is
// already scoped to the single project the manager serves.
func NewResolver(c client.Client) *Resolver {
	return &Resolver{Client: c, fetcher: ociBundleFetcher{}}
}

// newResolverWithFetcher injects a fetcher for tests.
func newResolverWithFetcher(c client.Client, f BundleFetcher) *Resolver {
	return &Resolver{Client: c, fetcher: f}
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
	if err := r.Get(ctx, client.ObjectKey{Name: revision}, rev); err != nil {
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

	imageRef, err := host.BundleImageRef(rev.Spec.Bundle)
	if err != nil {
		return host.WorkerDefinition{}, err
	}
	manifest, err := r.fetcher.Manifest(ctx, imageRef)
	if err != nil {
		return host.WorkerDefinition{}, fmt.Errorf("fetching bundle manifest: %w", err)
	}
	modulesByPath, err := r.fetcher.Modules(ctx, imageRef)
	if err != nil {
		return host.WorkerDefinition{}, fmt.Errorf("fetching bundle modules: %w", err)
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
	return host.BuildWorkerDefinition(manifest, rev.Spec.ServiceConfigSpec, source)
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
