// SPDX-License-Identifier: AGPL-3.0-only

package manager

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	workerdv1 "github.com/apoxy-dev/apoxy/api/workerd/v1"
	"github.com/apoxy-dev/apoxy/pkg/workerd/names"
)

// egressPushRetryAfter paces re-pushes while the tenant's resident (and so
// its egress control socket) is not up yet: resident creation is lazy on the
// first ServiceRevision reconcile and races this pusher on the same events.
const egressPushRetryAfter = 15 * time.Second

// EgressPusher is the data-plane half of the egress reconciler (APO-726): it
// compiles the tenant's egress plan from the project apiserver and pushes it
// to the CO-LOCATED resident over the per-tenant egress control socket
// (APO-723). One pusher instance runs per workerd-manager process and serves
// every tenant that process hosts; each pod pushes only to its own residents,
// so nothing is coordinated across pods. It is read-only on the API — status
// is written by the control-plane EgressStatusReconciler.
type EgressPusher struct {
	egressDir string

	mu    sync.Mutex
	gens  map[string]uint64
	conns map[string]*grpc.ClientConn
}

// NewEgressPusher returns a pusher over the egress control sockets under
// egressDir (the same directory the ResidentManager binds them in).
func NewEgressPusher(egressDir string) *EgressPusher {
	return &EgressPusher{
		egressDir: egressDir,
		gens:      make(map[string]uint64),
		conns:     make(map[string]*grpc.ClientConn),
	}
}

// nextGeneration mints the tenant's next config generation. Generations only
// need to be monotonic per resident lifetime: the resident's recorded state —
// and the generation guard with it — lives and dies with the sandbox, and a
// sandbox never outlives this process, so a process-local counter suffices.
// floor lifts the counter past a newer generation the resident reports having
// retained (a stale response), self-healing the ordering.
func (p *EgressPusher) nextGeneration(tenant string, floor uint64) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	gen := p.gens[tenant]
	if gen < floor {
		gen = floor
	}
	gen++
	p.gens[tenant] = gen
	return gen
}

// StopTenant drops the tenant's pusher state on project disengage: the
// generation counter and the cached control-socket connection.
func (p *EgressPusher) StopTenant(tenant string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.gens, tenant)
	if conn := p.conns[tenant]; conn != nil {
		_ = conn.Close()
		delete(p.conns, tenant)
	}
}

// conn returns the tenant's egress-control-socket connection, dialing and
// caching it on first use. grpc.NewClient is lazy (it does not connect until
// the first RPC) and the connection reconnects on its own when the resident is
// recreated on the same socket path, so one connection is reused across pushes.
func (p *EgressPusher) conn(tenant string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.conns[tenant]; c != nil {
		return c, nil
	}
	c, err := grpc.NewClient("unix://"+EgressSocketPath(p.egressDir, tenant),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	p.conns[tenant] = c
	return c, nil
}

// ReconcileWithClient compiles the tenant's egress plan with the given
// project-apiserver client and pushes it to the tenant's resident. The
// request is ignored: any egress-relevant event triggers a full push (the
// wire contract is whole-state, level-triggered). The multicluster wrapper in
// apoxy-cloud drives this per engaged project, mirroring
// ResidentManager.ReconcileWithClient.
func (p *EgressPusher) ReconcileWithClient(ctx context.Context, tenant string, c client.Client, _ ctrl.Request) (ctrl.Result, error) {
	plan, err := compileFromClient(ctx, c, true)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(plan.Services) == 0 {
		// Nothing serves, so no resident is expected (resident creation is
		// lazy on the first revision) and there is no state to reset: a
		// resident that served before is recreated fresh per revision set.
		return ctrl.Result{}, nil
	}

	gen := p.nextGeneration(tenant, 0)
	applied, err := p.push(ctx, tenant, gen, plan)
	switch {
	case status.Code(err) == codes.Unavailable:
		// The resident (or its socket) is not up yet, or is being torn down.
		slog.Debug("Egress push deferred; resident unavailable",
			"tenant", tenant, "error", err)
		return ctrl.Result{RequeueAfter: egressPushRetryAfter}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("pushing egress config: %w", err)
	case applied > gen:
		// A newer generation is retained (this process raced itself); lift
		// the counter past it and re-push once.
		gen = p.nextGeneration(tenant, applied)
		if applied, err = p.push(ctx, tenant, gen, plan); err != nil {
			return ctrl.Result{}, fmt.Errorf("re-pushing egress config past retained generation: %w", err)
		} else if applied > gen {
			return ctrl.Result{}, fmt.Errorf("egress config generation still stale after re-push (sent %d, retained %d)", gen, applied)
		}
	}

	slog.Debug("Pushed egress config", "tenant", tenant,
		"services", len(plan.Services), "generation", gen)
	return ctrl.Result{}, nil
}

// push sends one whole-state ApplyEgress to the tenant's resident over its
// egress control socket.
func (p *EgressPusher) push(ctx context.Context, tenant string, gen uint64, plan *EgressPlan) (uint64, error) {
	conn, err := p.conn(tenant)
	if err != nil {
		return 0, fmt.Errorf("dialing egress control socket: %w", err)
	}

	resp, err := workerdv1.NewEgressConfigClient(conn).ApplyEgress(ctx, &workerdv1.ApplyEgressRequest{
		SandboxId:  string(names.ResidentID(tenant)),
		Generation: gen,
		Services:   plan.WireConfigs(),
	})
	if err != nil {
		return 0, err
	}
	return resp.AppliedGeneration, nil
}

// TenantReconciler adapts the pusher to a plain reconcile.Func over one fixed
// tenant and client — the single-project (dedicated/dev) registration,
// mirroring ResidentManager.TenantReconciler.
func (p *EgressPusher) TenantReconciler(tenant string, c client.Client) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		return p.ReconcileWithClient(ctx, tenant, c, req)
	}
}
