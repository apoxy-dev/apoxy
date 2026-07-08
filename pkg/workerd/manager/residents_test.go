// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
)

const (
	tenantA = "7ce458d7-e20c-443c-aeeb-dbc5663c1240"
	tenantB = "11111111-2222-4333-8444-555555555555"
)

// fakeBuilder is an in-memory ResidentBuilder recording what was built.
type fakeBuilder struct {
	mu        sync.Mutex
	residents map[string]*fakeResident
	addrs     map[string]string
}

func newFakeBuilder() *fakeBuilder {
	return &fakeBuilder{residents: make(map[string]*fakeResident), addrs: make(map[string]string)}
}

func (b *fakeBuilder) NewResident(tenant, controlHostAddr string) (host.ResidentRuntime, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if controlHostAddr == "" {
		return nil, fmt.Errorf("no control addr")
	}
	r := &fakeResident{}
	b.residents[tenant] = r
	b.addrs[tenant] = controlHostAddr
	return r, nil
}

func (b *fakeBuilder) built(tenant string) *fakeResident {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.residents[tenant]
}

// addr reads a tenant's control address under the lock — the watcher goroutine
// can rebuild a tenant (rewriting the map) concurrently with test assertions.
func (b *fakeBuilder) addr(tenant string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addrs[tenant]
}

// newTestResidentManager wires a ResidentManager over the fake builder and the
// fake bundle fetcher so Warm succeeds without a registry.
func newTestResidentManager(b *fakeBuilder) *ResidentManager {
	m := NewResidentManager(b, "")
	m.newResolver = func(c client.Client) *Resolver {
		return newResolverWithFetcher(c, okFetcher())
	}
	return m
}

// reconcileTenant drives one reconcile like the controller would: transient
// "stopping; retrying" errors (a teardown in flight — e.g. the done-watcher
// repairing a killed control channel) are retried with a short backoff, since
// controller-runtime would requeue them.
func reconcileTenant(t *testing.T, m *ResidentManager, tenant string, c client.Client, revName string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := m.ReconcileWithClient(context.Background(), tenant, c,
			reconcile.Request{NamespacedName: types.NamespacedName{Name: revName}})
		if err == nil {
			return
		}
		if !strings.Contains(err.Error(), "stopping; retrying") || time.Now().After(deadline) {
			t.Fatalf("ReconcileWithClient(%q, %q): %v", tenant, revName, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// resolveVia asks a tenant's control server, over its real loopback listener,
// what revision it serves for service. Returns "" on a 404 (no live revision).
func resolveVia(t *testing.T, addr, service string) string {
	t.Helper()
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Get("http://" + addr + resolvePath + "?service=" + service)
	if err != nil {
		t.Fatalf("resolving %q via %s: %v", service, addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve %q via %s: status %d", service, addr, resp.StatusCode)
	}
	var rr resolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		t.Fatalf("decoding resolve response: %v", err)
	}
	return rr.Revision
}

// TestResidentManager_TwoTenantIsolation is the signature multi-tenant test:
// two projects with the SAME bare service name resolve to their own revisions
// through their own control listeners — neither can see the other's.
func TestResidentManager_TwoTenantIsolation(t *testing.T) {
	b := newFakeBuilder()
	m := newTestResidentManager(b)
	defer m.Close(context.Background())

	ca := newFakeClient(t, revision("api-aaaaa", "api", "sha256:a"))
	cb := newFakeClient(t, revision("api-bbbbb", "api", "sha256:b"))

	reconcileTenant(t, m, tenantA, ca, "api-aaaaa")
	reconcileTenant(t, m, tenantB, cb, "api-bbbbb")

	addrA, addrB := b.addr(tenantA), b.addr(tenantB)
	if addrA == addrB {
		t.Fatalf("tenants share a control address %q; per-tenant listeners must differ", addrA)
	}

	if got := resolveVia(t, addrA, "api"); got != "api-aaaaa" {
		t.Errorf("tenant A resolves api -> %q, want api-aaaaa", got)
	}
	if got := resolveVia(t, addrB, "api"); got != "api-bbbbb" {
		t.Errorf("tenant B resolves api -> %q, want api-bbbbb", got)
	}
	if b.built(tenantA).ensured() == 0 || b.built(tenantB).ensured() == 0 {
		t.Error("each tenant's resident should have been ensured during reconcile")
	}
}

// TestResidentManager_LazyCreation pins the lazy bring-up contract: engaging
// nothing costs nothing — a resident exists only after the tenant's first
// reconcile.
func TestResidentManager_LazyCreation(t *testing.T) {
	b := newFakeBuilder()
	m := newTestResidentManager(b)
	defer m.Close(context.Background())

	if b.built(tenantA) != nil {
		t.Fatal("no resident should exist before the first reconcile")
	}
	reconcileTenant(t, m, tenantA, newFakeClient(t, revision("api-aaaaa", "api", "sha256:a")), "api-aaaaa")
	if b.built(tenantA) == nil {
		t.Fatal("first reconcile should have built the tenant's resident")
	}
}

func TestResidentManager_RejectsInvalidTenant(t *testing.T) {
	m := newTestResidentManager(newFakeBuilder())
	defer m.Close(context.Background())

	c := newFakeClient(t)
	for _, tenant := range []string{"default", "../../etc", "A7E458D7-E20C-443C-AEEB-DBC5663C1240"} {
		if _, err := m.ReconcileWithClient(context.Background(), tenant, c,
			reconcile.Request{NamespacedName: types.NamespacedName{Name: "x"}}); err == nil {
			t.Errorf("tenant %q should be rejected", tenant)
		}
	}
}

// TestResidentManager_StopTenant asserts full per-tenant teardown: the
// resident is stopped, the control listener released, and other tenants are
// untouched. Stopping again (or an unknown tenant) is a no-op.
func TestResidentManager_StopTenant(t *testing.T) {
	b := newFakeBuilder()
	m := newTestResidentManager(b)
	defer m.Close(context.Background())

	reconcileTenant(t, m, tenantA, newFakeClient(t, revision("api-aaaaa", "api", "sha256:a")), "api-aaaaa")
	reconcileTenant(t, m, tenantB, newFakeClient(t, revision("web-bbbbb", "web", "sha256:b")), "web-bbbbb")
	addrA := b.addr(tenantA)

	if err := m.StopTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("StopTenant: %v", err)
	}
	if b.built(tenantA).stopped() != 1 {
		t.Errorf("tenant A resident stopCalls = %d, want 1", b.built(tenantA).stopped())
	}
	if _, err := (&http.Client{Timeout: time.Second}).Get("http://" + addrA + resolvePath + "?service=api"); err == nil {
		t.Error("tenant A control listener should be closed after StopTenant")
	}
	if got := resolveVia(t, b.addr(tenantB), "web"); got != "web-bbbbb" {
		t.Errorf("tenant B must survive A's teardown; resolves web -> %q", got)
	}
	if err := m.StopTenant(context.Background(), tenantA); err != nil {
		t.Errorf("second StopTenant should be a no-op, got %v", err)
	}
	if err := m.StopTenant(context.Background(), "22222222-3333-4444-8555-666666666666"); err != nil {
		t.Errorf("StopTenant of an unknown tenant should be a no-op, got %v", err)
	}
}

// TestResidentManager_SelfHealsDeadControlChannel kills a tenant's control
// serve goroutine and asserts the next reconcile rebuilds the whole entry —
// including a NEW sandbox (the old control address is sealed into the old
// sandbox's spec, so a new listener requires a new resident).
func TestResidentManager_SelfHealsDeadControlChannel(t *testing.T) {
	b := newFakeBuilder()
	m := newTestResidentManager(b)
	defer m.Close(context.Background())

	c := newFakeClient(t, revision("api-aaaaa", "api", "sha256:a"))
	reconcileTenant(t, m, tenantA, c, "api-aaaaa")
	first := b.built(tenantA)

	// Simulate the control serve goroutine dying out from under the entry.
	m.mu.Lock()
	entry := m.tenants[tenantA]
	m.mu.Unlock()
	entry.cancel()
	<-entry.done

	reconcileTenant(t, m, tenantA, c, "api-aaaaa")
	second := b.built(tenantA)
	if first == second {
		t.Fatal("a dead control channel should rebuild the tenant with a fresh resident")
	}
	if first.stopped() == 0 {
		t.Error("the old resident should be stopped during the rebuild")
	}
	if got := resolveVia(t, b.addr(tenantA), "api"); got != "api-aaaaa" {
		t.Errorf("rebuilt tenant resolves api -> %q, want api-aaaaa", got)
	}
}

// TestResidentManager_FailedTeardownIsRetryable pins the failed-disengage
// contract: a StopTenant whose resident refuses to stop surfaces the error and
// KEEPS the entry (rejected by reconciles as stopping), so a retry actually
// retries the teardown instead of no-opping while the sandbox runs orphaned.
func TestResidentManager_FailedTeardownIsRetryable(t *testing.T) {
	b := newFakeBuilder()
	m := newTestResidentManager(b)
	defer m.Close(context.Background())

	c := newFakeClient(t, revision("api-aaaaa", "api", "sha256:a"))
	reconcileTenant(t, m, tenantA, c, "api-aaaaa")
	fr := b.built(tenantA)

	fr.setStopErr(fmt.Errorf("runsc kill wedged"))
	if err := m.StopTenant(context.Background(), tenantA); err == nil {
		t.Fatal("StopTenant should surface a failed resident stop")
	}
	if _, err := m.ReconcileWithClient(context.Background(), tenantA, c,
		reconcile.Request{NamespacedName: types.NamespacedName{Name: "api-aaaaa"}}); err == nil {
		t.Fatal("a tenant with a failed teardown must reject reconciles instead of resurrecting the resident")
	}

	fr.setStopErr(nil)
	if err := m.StopTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("retried StopTenant should succeed: %v", err)
	}
	m.mu.Lock()
	_, still := m.tenants[tenantA]
	m.mu.Unlock()
	if still {
		t.Fatal("entry should be removed after the successful retry")
	}
}

// TestResidentManager_EagerRepairOnControlDeath asserts a dead control channel
// is FULLY repaired without waiting for a ServiceRevision event: the
// done-watcher tears the entry down, rebuilds it with the last client, boots
// the resident, and rewarms the store — a rebuilt-but-cold tenant would 404
// every /resolve until the next event, which may never come for a quiet tenant.
func TestResidentManager_EagerRepairOnControlDeath(t *testing.T) {
	b := newFakeBuilder()
	m := newTestResidentManager(b)
	defer m.Close(context.Background())

	c := newFakeClient(t, revision("api-aaaaa", "api", "sha256:a"))
	reconcileTenant(t, m, tenantA, c, "api-aaaaa")
	first := b.built(tenantA)

	// Kill the serve goroutine without marking the entry stopping.
	m.mu.Lock()
	entry := m.tenants[tenantA]
	m.mu.Unlock()
	entry.cancel()

	deadline := time.Now().Add(30 * time.Second)
	for {
		if second := b.built(tenantA); second != first && second.ensured() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watcher never repaired the tenant after control channel death")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if first.stopped() == 0 {
		t.Error("the old resident should be stopped during the eager repair")
	}
	// Full service restoration: the rewarmed store resolves through the NEW
	// control listener with no reconcile event having fired.
	for {
		if got := resolveVia(t, b.addr(tenantA), "api"); got == "api-aaaaa" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("repaired tenant's store was never rewarmed; /resolve stayed cold")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestResidentManager_NotFoundWithoutEntryCreatesNothing pins the straggler
// guard: a reconcile for a revision the client cannot produce (deleted, or a
// disengaged cluster's straggler event) must not create the tenant's whole
// assembly just to drain nothing.
func TestResidentManager_NotFoundWithoutEntryCreatesNothing(t *testing.T) {
	b := newFakeBuilder()
	m := newTestResidentManager(b)
	defer m.Close(context.Background())

	if _, err := m.ReconcileWithClient(context.Background(), tenantA, newFakeClient(t),
		reconcile.Request{NamespacedName: types.NamespacedName{Name: "gone-12345"}}); err != nil {
		t.Fatalf("NotFound without an entry should reconcile clean: %v", err)
	}
	if b.built(tenantA) != nil || m.hasTenant(tenantA) {
		t.Fatal("a NotFound reconcile must not create the tenant's entry")
	}
}

// TestResidentManager_EnsureTenant pins the eager single-project path: the
// empty tenant uses the fixed control address and the resident comes up
// without any reconcile.
func TestResidentManager_EnsureTenant(t *testing.T) {
	b := newFakeBuilder()
	m := NewResidentManager(b, "127.0.0.1:0") // fixed-addr slot, ephemeral in tests
	m.newResolver = func(c client.Client) *Resolver {
		return newResolverWithFetcher(c, okFetcher())
	}
	defer m.Close(context.Background())

	inst, err := m.EnsureTenant(context.Background(), "", newFakeClient(t))
	if err != nil {
		t.Fatalf("EnsureTenant: %v", err)
	}
	if inst == nil || b.built("") == nil || b.built("").ensured() != 1 {
		t.Fatal("EnsureTenant should build the empty tenant and ensure its resident eagerly")
	}
}
