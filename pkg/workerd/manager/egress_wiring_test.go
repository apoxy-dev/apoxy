// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	workerdv1 "github.com/apoxy-dev/apoxy/api/workerd/v1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/host"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

// egressFakeResident is a fakeResident that also applies egress, so the
// manager's EgressApplier probe wires the plane up for it.
type egressFakeResident struct {
	fakeResident
	fakeApplier
}

// egressFakeBuilder builds applier-capable residents.
type egressFakeBuilder struct {
	mu        sync.Mutex
	residents map[string]*egressFakeResident
}

func (b *egressFakeBuilder) NewResident(tenant, controlHostAddr string) (host.ResidentRuntime, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := &egressFakeResident{}
	if b.residents == nil {
		b.residents = make(map[string]*egressFakeResident)
	}
	b.residents[tenant] = r
	return r, nil
}

func (b *egressFakeBuilder) built(tenant string) *egressFakeResident {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.residents[tenant]
}

// dialEgress connects to a tenant's egress control socket.
func dialEgress(t *testing.T, dir, tenant string) workerdv1.EgressConfigClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+EgressSocketPath(dir, tenant),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dialing egress socket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return workerdv1.NewEgressConfigClient(conn)
}

// TestResidentManager_EgressPlaneWiring drives the whole manager-side plane
// end-to-end in process: a tenant's first reconcile binds the deterministic
// egress socket, a push over the real gRPC/UDS transport fans out to the
// resident's applier, and StopTenant reaps the socket.
func TestResidentManager_EgressPlaneWiring(t *testing.T) {
	dir := shortSockDir(t)
	b := &egressFakeBuilder{}
	m := NewResidentManager(b, "", WithEgressDir(dir))
	m.newResolver = func(c ctrlclient.Client) *Resolver { return newResolverWithFetcher(c, okFetcher()) }
	defer m.Close(context.Background())

	reconcileTenant(t, m, tenantA, newFakeClient(t, revision("api-aaaaa", "api", "sha256:a")), "api-aaaaa")

	sock := EgressSocketPath(dir, tenantA)
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("egress socket not bound after first reconcile: %v", err)
	}

	client := dialEgress(t, dir, tenantA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.ApplyEgress(ctx, &workerdv1.ApplyEgressRequest{
		SandboxId: string(names.ResidentID(tenantA)),
		Services: []*workerdv1.ServiceEgressConfig{{
			Service: "api",
			Policy:  &workerdv1.EgressPolicy{DefaultDeny: true},
		}},
		InvocationId: "inv-1",
		Generation:   4,
	})
	if err != nil {
		t.Fatalf("ApplyEgress over the tenant socket: %v", err)
	}
	if resp.AppliedGeneration != 4 {
		t.Errorf("AppliedGeneration = %d; want 4", resp.AppliedGeneration)
	}
	applies := b.built(tenantA).applied()
	if len(applies) != 1 || applies[0].InvocationID != "inv-1" ||
		len(applies[0].Services) != 1 || applies[0].Services[0].Service != "api" ||
		applies[0].Services[0].Policy == nil || !applies[0].Services[0].Policy.DefaultDeny {
		t.Errorf("resident applier saw %+v; want the pushed config", applies)
	}

	if err := m.StopTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("StopTenant: %v", err)
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("egress socket still present after StopTenant: %v", err)
	}
}

// TestResidentManager_EgressPlaneDisabled covers the two disabled shapes: no
// egress dir configured, and a resident implementation that cannot apply
// egress — both must leave the tenant fully serviceable with no socket.
func TestResidentManager_EgressPlaneDisabled(t *testing.T) {
	t.Run("no egress dir", func(t *testing.T) {
		b := newFakeBuilder()
		m := newTestResidentManager(b)
		defer m.Close(context.Background())
		reconcileTenant(t, m, tenantA, newFakeClient(t, revision("api-aaaaa", "api", "sha256:a")), "api-aaaaa")
	})

	t.Run("resident without EgressApplier", func(t *testing.T) {
		dir := shortSockDir(t)
		b := newFakeBuilder() // plain fakeResident: no ApplyEgress
		m := NewResidentManager(b, "", WithEgressDir(dir))
		m.newResolver = func(c ctrlclient.Client) *Resolver { return newResolverWithFetcher(c, okFetcher()) }
		defer m.Close(context.Background())

		reconcileTenant(t, m, tenantA, newFakeClient(t, revision("api-aaaaa", "api", "sha256:a")), "api-aaaaa")
		if _, err := os.Stat(EgressSocketPath(dir, tenantA)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("socket bound for a non-applier resident: %v", err)
		}
	})
}
