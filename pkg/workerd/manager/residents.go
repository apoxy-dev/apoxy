// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

// teardownTimeout bounds the internally initiated teardowns (dead-entry repair
// on the reconcile path, the done-watcher): runsc kill/delete is hang-prone,
// and an unbounded Stop would pin the reconcile worker for every tenant.
// Caller-initiated StopTenant/Close run on the caller's context instead.
const teardownTimeout = 2 * time.Minute

// repairTimeout bounds a full eager repair (resident boot + store rewarm); the
// resident boot may pull the workerd image, so it is generous.
const repairTimeout = 5 * time.Minute

// ResidentManager owns the per-tenant workerd residents of one manager
// process. Each tenant (project UUID; "" for single-project topologies) gets
// its own resident sandbox, warm Store, and control listener — the hard
// isolation boundary: a tenant's dispatcher can only reach the control server
// whose address was sealed into its own sandbox spec, so it can never resolve
// another project's services.
//
// It follows the tunnelproxy embedding pattern (TunnelServer.
// ReconcileWithClient): the core is client-parameterized and holds NO
// multicluster machinery. Single-project callers (Run) drive it with the empty
// tenant and their own client; apoxy-cloud's shared backplane wraps it in an
// mcreconcile.Reconciler that resolves req.ClusterName to a cluster client and
// delegates here, and calls StopTenant when a project disengages from the
// shard. Tenant entries are created lazily on first reconcile, so an engaged
// project with no ServiceRevisions costs no sandbox.
type ResidentManager struct {
	factory ResidentBuilder
	// controlAddr is the fixed control address for the empty tenant (the
	// single-project resident, historically 127.0.0.1:2024). Project tenants
	// bind ephemeral loopback ports instead — their address is sealed into the
	// sandbox spec, not part of any cross-process contract.
	controlAddr string
	// newResolver builds a tenant's resolver from its project client;
	// overridden in tests to inject a fake bundle fetcher.
	newResolver func(client.Client) *Resolver

	mu      sync.Mutex
	tenants map[string]*tenantEntry
	// draining marks tenants with a StopTenant in flight. Entry creation is
	// refused for a draining tenant, which closes the race where the
	// done-watcher rebuilds an entry concurrently with a deliberate stop and
	// the rebuilt entry escapes the stop's identity-guarded removal.
	draining map[string]bool
}

// ResidentBuilder constructs per-tenant residents. *host.ResidentFactory is
// the production implementation; tests fake it on any platform.
type ResidentBuilder interface {
	NewResident(tenant, controlHostAddr string) (host.ResidentRuntime, error)
}

// tenantEntry is one tenant's running assembly. Its control serve goroutine
// lives for the entry's lifetime; done/err surface its exit so an unexpected
// death is repaired eagerly (and, as a backstop, on the next reconcile) — a
// fresh listener address requires a fresh sandbox, since the old address is
// baked into the spec.
type tenantEntry struct {
	tenant   string
	resident host.ResidentRuntime
	store    *Store
	resolver *Resolver

	controlAddr string
	cancel      context.CancelFunc
	done        chan struct{}
	err         error // control serve exit error; read only after done is closed

	// stopping (guarded by ResidentManager.mu) marks a teardown in flight so
	// reconciles stop using the entry and the done-watcher knows the exit was
	// deliberate. lifecycle excludes teardown from in-flight reconciles: users
	// hold RLock while driving the resident, so Stop cannot yank a sandbox out
	// from under a reconcile (which would resurrect it as an untracked orphan).
	stopping  bool
	lifecycle sync.RWMutex
}

// NewResidentManager returns a manager over factory. controlAddr is the fixed
// control address used for the empty tenant; project tenants always bind
// ephemeral loopback ports.
func NewResidentManager(factory ResidentBuilder, controlAddr string) *ResidentManager {
	return &ResidentManager{
		factory:     factory,
		controlAddr: controlAddr,
		newResolver: NewResolver,
		tenants:     make(map[string]*tenantEntry),
		draining:    make(map[string]bool),
	}
}

// ReconcileWithClient reconciles one tenant's ServiceRevision using the
// provided project-scoped client. This is the seam both the single-project
// controller (Run) and apoxy-cloud's multicluster wrapper call — mirroring
// TunnelServer.ReconcileWithClient.
//
// The revision is fetched BEFORE any tenant state is created, so a reconcile
// arriving with a disengaged cluster's client (stopped cache) errors out
// without resurrecting the tenant, and a deletion event for a tenant with no
// live entry creates nothing just to drain it.
func (m *ResidentManager) ReconcileWithClient(ctx context.Context, tenant string, c client.Client, req ctrl.Request) (ctrl.Result, error) {
	if err := names.ValidateTenant(tenant); err != nil {
		return ctrl.Result{}, err
	}
	rev := &computev1alpha1.ServiceRevision{}
	if err := c.Get(ctx, req.NamespacedName, rev); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("fetching service revision: %w", err)
		}
		if !m.hasTenant(tenant) {
			return ctrl.Result{}, nil
		}
	}

	entry, err := m.tenant(tenant, c)
	if err != nil {
		return ctrl.Result{}, err
	}
	entry.lifecycle.RLock()
	defer entry.lifecycle.RUnlock()
	if m.isStopping(entry) {
		return ctrl.Result{}, fmt.Errorf("workerd tenant %q is stopping; retrying", tenant)
	}
	return NewResidentReconciler(c, entry.resident, entry.store).Reconcile(ctx, req)
}

// EnsureTenant creates the tenant's entry if needed and brings its resident up
// eagerly, returning the running instance. Single-project Run uses it for
// boot-time fail-fast; shared shards skip it and let the first ServiceRevision
// reconcile bring the resident up lazily.
func (m *ResidentManager) EnsureTenant(ctx context.Context, tenant string, c client.Client) (*host.ResidentInstance, error) {
	entry, err := m.tenant(tenant, c)
	if err != nil {
		return nil, err
	}
	entry.lifecycle.RLock()
	defer entry.lifecycle.RUnlock()
	if m.isStopping(entry) {
		return nil, fmt.Errorf("workerd tenant %q is stopping; retrying", tenant)
	}
	return entry.resident.EnsureResident(ctx)
}

// StopTenant tears down a tenant's assembly: control serve goroutine,
// listener, resident sandbox, and staged config. Idempotent — stopping an
// unknown tenant is a no-op, and a failed teardown leaves the entry in place
// (marked stopping, rejected by reconciles) so a retry actually retries
// instead of silently orphaning a running sandbox. The multicluster wrapper
// calls this when the project disengages from the shard.
//
// While it runs, the tenant is marked draining: entry creation (reconcile or
// done-watcher rebuild) is refused, and it loops until no entry remains, so a
// rebuild racing the stop cannot escape it.
func (m *ResidentManager) StopTenant(ctx context.Context, tenant string) error {
	m.mu.Lock()
	m.draining[tenant] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.draining, tenant)
		m.mu.Unlock()
	}()

	for {
		m.mu.Lock()
		entry, ok := m.tenants[tenant]
		m.mu.Unlock()
		if !ok {
			return nil
		}
		if err := m.stopEntry(ctx, entry); err != nil {
			return err
		}
	}
}

// Close stops every tenant. Used at process shutdown; per-tenant errors are
// joined so one failing teardown doesn't hide the rest.
func (m *ResidentManager) Close(ctx context.Context) error {
	m.mu.Lock()
	tenants := make([]string, 0, len(m.tenants))
	for t := range m.tenants {
		tenants = append(tenants, t)
	}
	m.mu.Unlock()

	var errs []error
	for _, t := range tenants {
		if err := m.StopTenant(ctx, t); err != nil {
			errs = append(errs, fmt.Errorf("tenant %q: %w", t, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("stopping residents: %w", errors.Join(errs...))
	}
	return nil
}

// stopEntry is the single teardown path: mark the entry stopping (reconciles
// reject it, the done-watcher stands down), wait out in-flight reconciles via
// the lifecycle write lock, tear down, and only THEN remove the entry from the
// map — so a failed teardown stays visible and retryable rather than leaking
// an untracked running sandbox. Idempotent and safe to race: concurrent calls
// serialize on lifecycle, teardown re-runs harmlessly, and the map removal is
// identity-guarded.
func (m *ResidentManager) stopEntry(ctx context.Context, entry *tenantEntry) error {
	m.mu.Lock()
	entry.stopping = true
	m.mu.Unlock()

	entry.lifecycle.Lock()
	defer entry.lifecycle.Unlock()
	if err := m.teardown(ctx, entry); err != nil {
		return err
	}
	m.mu.Lock()
	if m.tenants[entry.tenant] == entry {
		delete(m.tenants, entry.tenant)
	}
	m.mu.Unlock()
	return nil
}

// teardown stops one entry's serve goroutine and resident. Idempotent: cancel
// is a no-op after the first call, done is already closed, and a stopped
// resident's Stop returns nil.
func (m *ResidentManager) teardown(ctx context.Context, entry *tenantEntry) error {
	entry.cancel()
	<-entry.done
	slog.Info("Stopped workerd control channel", "tenant", entry.tenant, "addr", entry.controlAddr)
	if err := entry.resident.Stop(ctx); err != nil {
		return fmt.Errorf("stopping resident: %w", err)
	}
	return nil
}

// isStopping reads the entry's stopping mark under the manager lock.
func (m *ResidentManager) isStopping(entry *tenantEntry) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return entry.stopping
}

// hasTenant reports whether the tenant currently has an entry.
func (m *ResidentManager) hasTenant(tenant string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.tenants[tenant]
	return ok
}

// tenant returns the live entry for tenant, creating it (or rebuilding a dead
// one) as needed, and rebinds the entry's resolver to the caller's client so a
// re-engaged project's fresh client takes effect on the control pull path too.
func (m *ResidentManager) tenant(tenant string, c client.Client) (*tenantEntry, error) {
	if err := names.ValidateTenant(tenant); err != nil {
		return nil, err
	}

	m.mu.Lock()
	entry, ok := m.tenants[tenant]
	stopping := ok && entry.stopping
	m.mu.Unlock()
	if ok {
		if stopping {
			// A deliberate teardown owns this entry (in flight, or failed and
			// awaiting a StopTenant retry). Never rebuild over it — that would
			// resurrect a disengaged tenant.
			return nil, fmt.Errorf("workerd tenant %q is stopping; retrying", tenant)
		}
		select {
		case <-entry.done:
			// The control serve goroutine died out from under the entry. The old
			// address is baked into the running sandbox's spec, so a new listener
			// means a new sandbox: tear down (bounded — runsc is hang-prone) and
			// rebuild below.
			slog.Warn("Workerd control channel is down; rebuilding tenant",
				"tenant", tenant, "addr", entry.controlAddr, "error", entry.err)
			stopCtx, cancel := context.WithTimeout(context.Background(), teardownTimeout)
			err := m.stopEntry(stopCtx, entry)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("tearing down dead tenant %q: %w", tenant, err)
			}
		default:
			entry.resolver.setClient(c)
			return entry, nil
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining[tenant] {
		return nil, fmt.Errorf("workerd tenant %q is stopping; retrying", tenant)
	}
	// Re-check under the lock: a concurrent reconcile may have built it first.
	if entry, ok := m.tenants[tenant]; ok {
		entry.resolver.setClient(c)
		return entry, nil
	}

	resolver := m.newResolver(c)
	store := NewStore(resolver)
	control := NewControlServer(store)
	bound, err := control.Listen(m.controlAddrFor(tenant))
	if err != nil {
		return nil, err
	}
	resident, err := m.factory.NewResident(tenant, bound)
	if err != nil {
		control.Close()
		return nil, err
	}

	// The serve goroutine outlives any single reconcile, so it runs on the
	// entry's own context, cancelled by teardown — not on the reconcile ctx.
	serveCtx, cancel := context.WithCancel(context.Background())
	entry = &tenantEntry{
		tenant:      tenant,
		resident:    resident,
		store:       store,
		resolver:    resolver,
		controlAddr: bound,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
	go func() {
		err := control.Serve(serveCtx)
		if err != nil {
			slog.Error("Workerd control channel exited", "tenant", tenant, "addr", bound, "error", err)
		}
		entry.err = err
		close(entry.done)
	}()
	go m.watchEntry(entry)

	slog.Info("Created workerd tenant", "tenant", tenant, "controlAddr", bound)
	m.tenants[tenant] = entry
	return entry, nil
}

// watchEntry repairs a tenant whose control channel died out from under it,
// without waiting for the next ServiceRevision event (which may never come for
// an otherwise-quiet tenant). Repair is FULL service restoration, matching
// what the pre-per-tenant path got from a process restart: tear down, rebuild
// the entry, boot the resident, and rewarm the store from a ServiceRevision
// re-list — a rebuilt entry with a cold store would 404 every /resolve until
// the next event. A deliberate teardown (stopping set before cancel) stands
// down; a failed repair is left to the reconcile-path backstop in tenant().
func (m *ResidentManager) watchEntry(entry *tenantEntry) {
	<-entry.done
	if m.isStopping(entry) {
		return
	}
	slog.Warn("Workerd control channel died; repairing tenant eagerly",
		"tenant", entry.tenant, "addr", entry.controlAddr, "error", entry.err)
	stopCtx, cancel := context.WithTimeout(context.Background(), teardownTimeout)
	err := m.stopEntry(stopCtx, entry)
	cancel()
	if err != nil {
		slog.Error("Failed to tear down dead workerd tenant; a reconcile will retry",
			"tenant", entry.tenant, "error", err)
		return
	}
	repairCtx, cancel := context.WithTimeout(context.Background(), repairTimeout)
	defer cancel()
	if err := m.repairTenant(repairCtx, entry.tenant, entry.resolver.getClient()); err != nil {
		slog.Error("Failed to repair workerd tenant after control channel death",
			"tenant", entry.tenant, "error", err)
	}
}

// repairTenant restores a tenant to full service: entry (re)built, resident
// running, store rewarmed from a full ServiceRevision re-list. Per-revision
// rewarm failures are logged and skipped — each will be retried by its own
// reconcile — so one broken bundle doesn't leave the rest of the tenant cold.
func (m *ResidentManager) repairTenant(ctx context.Context, tenant string, c client.Client) error {
	if _, err := m.EnsureTenant(ctx, tenant, c); err != nil {
		return err
	}
	revs := &computev1alpha1.ServiceRevisionList{}
	if err := c.List(ctx, revs); err != nil {
		return fmt.Errorf("listing service revisions: %w", err)
	}
	for i := range revs.Items {
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&revs.Items[i])}
		if _, err := m.ReconcileWithClient(ctx, tenant, c, req); err != nil {
			slog.Warn("Failed to rewarm service revision during tenant repair",
				"tenant", tenant, "revision", req.Name, "error", err)
		}
	}
	return nil
}

// controlAddrFor picks the control bind address for a tenant: the fixed
// single-project address for the empty tenant, an ephemeral loopback port for
// project tenants.
func (m *ResidentManager) controlAddrFor(tenant string) string {
	if tenant == "" && m.controlAddr != "" {
		return m.controlAddr
	}
	return "127.0.0.1:0"
}

// TenantReconciler adapts one tenant + client pair to a reconcile.Reconciler
// for controller-runtime registration (the single-project path). Multicluster
// callers skip this and call ReconcileWithClient with the per-request cluster
// client instead.
func (m *ResidentManager) TenantReconciler(tenant string, c client.Client) reconcile.Func {
	return func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
		return m.ReconcileWithClient(ctx, tenant, c, req)
	}
}
