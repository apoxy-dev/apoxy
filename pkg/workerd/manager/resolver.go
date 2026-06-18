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

// Resolver turns a dispatcher demux id ("<project>:<service>:<revision>") into
// the host.WorkerDefinition the WorkerLoader callback consumes: it loads the
// ServiceRevision, pulls its bundle, and reconstructs the WorkerCode payload.
//
// The id is project-qualified so the one shared resident's WorkerLoader cache
// (and the backplane demux) never collide two projects' same-named Services.
type Resolver struct {
	client.Client
	fetcher   BundleFetcher
	projectID string
}

// NewResolver returns a Resolver over the production OCI fetcher, scoped to the
// project the manager serves.
func NewResolver(c client.Client, projectID string) *Resolver {
	return &Resolver{Client: c, fetcher: ociBundleFetcher{}, projectID: projectID}
}

// newResolverWithFetcher injects a fetcher for tests.
func newResolverWithFetcher(c client.Client, projectID string, f BundleFetcher) *Resolver {
	return &Resolver{Client: c, fetcher: f, projectID: projectID}
}

// Resolve builds the WorkerDefinition for a demux id. A missing ServiceRevision
// is reported as errRevisionNotFound (wrapped) so the control server can answer
// 404; pull/build failures propagate as-is (a 502 the dispatcher surfaces).
func (r *Resolver) Resolve(ctx context.Context, id string) (host.WorkerDefinition, error) {
	project, service, revision, err := splitServiceID(id)
	if err != nil {
		return host.WorkerDefinition{}, err
	}
	// Defense in depth: a request for another project's id must never resolve
	// against this project-scoped manager.
	if r.projectID != "" && project != r.projectID {
		return host.WorkerDefinition{}, fmt.Errorf("id %q targets project %q, not %q", id, project, r.projectID)
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

// splitServiceID parses the dispatcher demux id "<project>:<service>:<revision>".
// All three are DNS-1123 names (no colon), so two ":" separate them.
func splitServiceID(id string) (project, service, revision string, err error) {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("workerd-manager: invalid service id %q (want %q)", id, "<project>:<service>:<revision>")
	}
	return parts[0], parts[1], parts[2], nil
}

// serviceRevisionID is the demux id for a ServiceRevision:
// "<project>:<service>:<name>". The service comes from the serviceLabel the
// minting reconciler sets; the project scopes the id so the shared resident's
// isolate cache never collides two projects' same-named services.
func serviceRevisionID(projectID string, rev *computev1alpha1.ServiceRevision) (string, error) {
	service := rev.Labels[serviceLabel]
	if service == "" {
		return "", fmt.Errorf("workerd-manager: revision %q has no %s label", rev.Name, serviceLabel)
	}
	if projectID == "" {
		return "", fmt.Errorf("workerd-manager: no project id configured; cannot build demux id for %q", rev.Name)
	}
	return projectID + ":" + service + ":" + rev.Name, nil
}

// serviceDemuxKey is the per-service demux map key the backplane looks up:
// "<project>:<service>". The header it builds is this key plus ":<liveRevision>".
func serviceDemuxKey(projectID, service string) string {
	return projectID + ":" + service
}
