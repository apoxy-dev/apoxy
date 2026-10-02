package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/metrics"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// LabelRelay is the name of the relay that wrote a Tunnel.
const LabelRelay = "vpc.apoxy.dev/relay"

const (
	syncScanInterval = time.Second
	syncRetryCap     = 30 * time.Second
	syncTimeout      = 10 * time.Second
	// syncParallelism is the maximum number of Tunnel writes in flight for one
	// publisher, so a slow write does not delay the writes of other connections.
	syncParallelism = 16
)

// vniAllocator is the part of *vni.VNIAllocator that the publisher uses.
type vniAllocator interface {
	Allocate() (uint, error)
	Release(vni uint)
}

// TunnelPublisher assigns each connection its addresses and VNI with no
// apiserver call. A worker writes and deletes the Tunnel objects later.
type TunnelPublisher struct {
	client    client.Client
	relayName string
	relay     Relay
	slots     *slotAllocator
	vnis      vniAllocator

	mu       sync.Mutex
	networks map[string]tunnet.NetworkID // VPCNetwork name -> NetworkID
	tunnels  map[string]*tunnelState     // Tunnel name (connection ID) -> state

	// holdCreates stops Tunnel creates while a bulk delete of this relay's Tunnels
	// runs.
	holdCreates bool
	// resyncMu makes Resync calls run one at a time.
	resyncMu sync.Mutex

	wake       chan struct{}
	syncSlots  chan struct{} // one token per Tunnel write in flight
	stopWorker context.CancelFunc
	workerDone chan struct{}
	stopOnce   sync.Once
}

// connAlloc records what one connection was assigned.
type connAlloc struct {
	alloc *ipalloc.ConnAllocator
	v6    netip.Prefix
	v4    netip.Prefix
	vni   uint
	slot  ipalloc.Slot

	// tunnel is the object to publish. It is nil for a connection that
	// failed setup and only waits for its disconnect.
	tunnel    *vpcv1alpha1.Tunnel
	published bool
}

// staleAlloc records a Tunnel of this relay that no connection here owns. It
// holds no addresses.
func staleAlloc() *connAlloc { return &connAlloc{} }

// tunnelState tracks one Tunnel name. An allocation is freed only when it is
// neither live nor written.
type tunnelState struct {
	live    *connAlloc // the connection that now uses this ID
	written *connAlloc // the connection whose Tunnel can exist in the apiserver

	busy     bool
	attempts int
	retryAt  time.Time
	// pendingSince is when the oldest waiting write became due, or zero.
	pendingSince time.Time
}

// markPending records that a write became due at now, unless an older one
// waits.
func (st *tunnelState) markPending(now time.Time) {
	if st.pendingSince.IsZero() {
		st.pendingSince = now
	}
}

// needsDelete reports whether a Tunnel of a closed connection can still exist.
func (st *tunnelState) needsDelete() bool {
	return st.written != nil && st.written != st.live
}

// needsCreate reports whether the live connection has no confirmed Tunnel.
func (st *tunnelState) needsCreate() bool {
	return st.live != nil && st.live.tunnel != nil && !st.live.published
}

// NewTunnelPublisher creates a TunnelPublisher and wires it to the relay's
// connect/disconnect callbacks.
func NewTunnelPublisher(c client.Client, relay Relay, leaser ipalloc.SlotLeaser, vnis vniAllocator) *TunnelPublisher {
	ctx, cancel := context.WithCancel(context.Background())
	p := &TunnelPublisher{
		client:     c,
		relayName:  relay.Name(),
		relay:      relay,
		slots:      newSlotAllocator(leaser),
		vnis:       vnis,
		networks:   make(map[string]tunnet.NetworkID),
		tunnels:    make(map[string]*tunnelState),
		wake:       make(chan struct{}, 1),
		syncSlots:  make(chan struct{}, syncParallelism),
		stopWorker: cancel,
		workerDone: make(chan struct{}),
	}
	relay.SetOnConnect(p.OnConnect)
	relay.SetOnDisconnect(p.OnDisconnect)
	go p.run(ctx)
	return p
}

// SetNetworkID records the NetworkID of a VPCNetwork name and leases a spare
// slot for it.
func (p *TunnelPublisher) SetNetworkID(name string, id tunnet.NetworkID) {
	p.mu.Lock()
	p.networks[name] = id
	p.mu.Unlock()
	p.slots.EnsureSpare(id)
}

// RemoveNetwork forgets a deleted VPCNetwork and returns all of its slots.
func (p *TunnelPublisher) RemoveNetwork(ctx context.Context, name string) {
	p.mu.Lock()
	id, ok := p.networks[name]
	delete(p.networks, name)
	p.mu.Unlock()
	if ok {
		for _, id := range p.connectionIDsForNetwork(id) {
			p.relay.DisconnectConnection(id)
		}
		p.slots.ReleaseNetwork(ctx, id)
	}
}

// AssignAddress takes a /96 from the held slots for a user that is not a
// connection. It writes no Tunnel. Call release to free the /96.
func (p *TunnelPublisher) AssignAddress(ctx context.Context, network tunnet.NetworkID) (v6 netip.Prefix, release func(), err error) {
	v6, v4, alloc, err := p.slots.Allocate(ctx, network)
	if err != nil {
		return netip.Prefix{}, nil, fmt.Errorf("failed to allocate an overlay address: %w", err)
	}
	// Only the /96 is used.
	p.slots.Release(alloc, netip.Prefix{}, v4)
	if !p.slots.Contains(alloc) {
		p.slots.Release(alloc, v6, netip.Prefix{})
		slot := alloc.Slot()
		return netip.Prefix{}, nil, fmt.Errorf("overlay slot %s generation %d is no longer held", ipalloc.SlotLabelValue(slot), slot.Generation)
	}
	var once sync.Once
	return v6, func() { once.Do(func() { p.slots.Release(alloc, v6, netip.Prefix{}) }) }, nil
}

// InvalidateSlot drops a slot the leaser lost so no new connections allocate
// from it. Wired to the leaser's slot-lost notification where one exists.
func (p *TunnelPublisher) InvalidateSlot(s ipalloc.Slot) {
	p.mu.Lock()
	p.slots.InvalidateSlot(s)
	ids := make([]string, 0)
	for id, st := range p.tunnels {
		if st.live != nil && sameSlotGeneration(st.live.slot, s) {
			ids = append(ids, id)
		}
	}
	p.mu.Unlock()
	metrics.TunnelSlotLosses.Inc()
	for _, id := range ids {
		p.relay.DisconnectConnection(id)
	}
}

// OnConnect gives the connection its addresses and VNI. It makes no apiserver
// call.
func (p *TunnelPublisher) OnConnect(ctx context.Context, tunnelName, agentName string, conn Connection) error {
	id := conn.ID()
	networkName := conn.Network()

	p.mu.Lock()
	if st := p.tunnels[id]; st != nil && st.live != nil {
		p.mu.Unlock()
		return fmt.Errorf("connection ID %q is already active", id)
	}
	netID, ok := p.networks[networkName]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("network %q is not provisioned yet", networkName)
	}

	v6, v4, alloc, err := p.slots.Allocate(ctx, netID)
	if err != nil {
		return fmt.Errorf("failed to allocate connection addresses: %w", err)
	}
	slot := alloc.Slot()
	if !p.slots.Contains(alloc) {
		p.slots.Release(alloc, v6, v4)
		return fmt.Errorf("overlay slot %s generation %d is no longer held", ipalloc.SlotLabelValue(slot), slot.Generation)
	}

	vniID, err := p.vnis.Allocate()
	if err != nil {
		p.slots.Release(alloc, v6, v4)
		return fmt.Errorf("failed to allocate VNI: %w", err)
	}
	rec := &connAlloc{alloc: alloc, v6: v6, v4: v4, vni: vniID, slot: slot}

	// Program the router with the primary (IPv6 /96) address, then install the
	// VNI (which derives its allowed routes from the overlay address).
	if err := conn.SetOverlayAddress(v6.String()); err != nil {
		p.release(rec)
		return fmt.Errorf("failed to set overlay address: %w", err)
	}
	// The router now holds state for v6, so only the relay teardown frees the
	// allocation. A direct release can give the /96 to another connect (EEXIST).
	if err := conn.SetVNI(ctx, vniID); err != nil {
		p.setLive(id, rec)
		return fmt.Errorf("failed to set VNI: %w", err)
	}

	addresses := []string{v6.String()}
	if v4.IsValid() {
		addresses = append(addresses, v4.String())
	}
	if err := conn.SetAddresses(addresses); err != nil {
		// The /32 is optional: drop it and use v6 only.
		if !v4.IsValid() {
			p.setLive(id, rec)
			return fmt.Errorf("failed to set overlay addresses: %w", err)
		}
		slog.Warn("Failed to program the IPv4 overlay address, continuing without v4",
			slog.String("connID", id),
			slog.String("v4", v4.String()),
			slog.Any("error", err))
		p.slots.Release(alloc, netip.Prefix{}, v4)
		rec.v4 = netip.Prefix{}
		addresses = addresses[:1]
		if err := conn.SetAddresses(addresses); err != nil {
			p.setLive(id, rec)
			return fmt.Errorf("failed to set overlay addresses: %w", err)
		}
	}

	tunnel := p.newTunnel(conn, networkName, agentName, addresses, slot)
	p.mu.Lock()
	slotHeld := p.slots.Contains(alloc)
	currentNetID, networkExists := p.networks[networkName]
	current := slotHeld && networkExists && currentNetID == netID
	st := p.state(id)
	if current {
		rec.tunnel = tunnel
		st.markPending(time.Now())
	}
	st.live = rec
	p.mu.Unlock()
	if !slotHeld {
		return fmt.Errorf("overlay slot %s generation %d was lost during connection setup", ipalloc.SlotLabelValue(slot), slot.Generation)
	}
	if !current {
		return fmt.Errorf("network %q was removed during connection setup", networkName)
	}
	p.wakeWorker()

	slog.Info("Accepted tunnel connection",
		slog.String("connID", id),
		slog.String("network", networkName),
		slog.String("agent", agentName),
		slog.String("v6", v6.String()))
	return nil
}

// OnDisconnect ends the connection's use of its ID. A written allocation is
// freed after the worker confirms the Tunnel delete.
func (p *TunnelPublisher) OnDisconnect(_ context.Context, _, id string) error {
	p.mu.Lock()
	st := p.tunnels[id]
	if st == nil || st.live == nil {
		p.mu.Unlock()
		return nil
	}
	rec := st.live
	st.live = nil
	st.retryAt = time.Time{}
	written := st.written == rec
	if written {
		st.markPending(time.Now())
	} else {
		p.release(rec)
	}
	if st.written == nil {
		delete(p.tunnels, id)
	}
	p.mu.Unlock()

	if written {
		metrics.TunnelCleanupPending.Inc()
		p.wakeWorker()
	}
	return nil
}

// state returns the Tunnel state for id, creating it on first use. The caller
// must hold mu.
func (p *TunnelPublisher) state(id string) *tunnelState {
	st := p.tunnels[id]
	if st == nil {
		st = &tunnelState{}
		p.tunnels[id] = st
	}
	return st
}

// setLive records the allocation of a connection that failed setup, so its
// disconnect releases it.
func (p *TunnelPublisher) setLive(id string, rec *connAlloc) {
	p.mu.Lock()
	p.state(id).live = rec
	p.mu.Unlock()
}

// release returns a connection's addresses and VNI to their pools. The
// caller holds mu, or owns rec alone.
func (p *TunnelPublisher) release(rec *connAlloc) {
	if rec.alloc == nil {
		return // A stale Tunnel holds nothing.
	}
	p.slots.Release(rec.alloc, rec.v6, rec.v4)
	p.vnis.Release(rec.vni)
}

// newTunnel builds the Tunnel object with addresses and routes in status. It
// is not patched after create.
func (p *TunnelPublisher) newTunnel(conn Connection, networkName, agentName string, addresses []string, slot ipalloc.Slot) *vpcv1alpha1.Tunnel {
	return &vpcv1alpha1.Tunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name:   conn.ID(),
			Labels: p.tunnelLabels(conn, networkName, agentName, slot),
		},
		Spec: vpcv1alpha1.TunnelSpec{
			NetworkRef: vpcv1alpha1.VPCNetworkRef{Name: networkName},
			RelayRef:   vpcv1alpha1.RelayRef{Name: p.relayName},
		},
		Status: vpcv1alpha1.TunnelStatus{
			Addresses:        addresses,
			AdvertisedRoutes: prefixesToStrings(conn.AdvertisedRoutes()),
		},
	}
}

// createTunnel creates want and then writes its status. A Tunnel of an older
// connection is deleted, and the next attempt creates want.
func (p *TunnelPublisher) createTunnel(ctx context.Context, want *vpcv1alpha1.Tunnel) error {
	t := want.DeepCopy()
	if err := p.client.Create(ctx, t); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		if err := p.client.Get(ctx, client.ObjectKeyFromObject(want), t); err != nil {
			return err
		}
		if !sameConnection(t, want) {
			if err := p.client.Delete(ctx, t); client.IgnoreNotFound(err) != nil {
				return err
			}
			return fmt.Errorf("tunnel %s of an older connection was still present", want.Name)
		}
	}
	t.Status = *want.Status.DeepCopy()
	return p.client.Status().Update(ctx, t)
}

// sameConnection reports whether two Tunnels describe one connection: the
// same relay, slot and slot generation.
func sameConnection(a, b *vpcv1alpha1.Tunnel) bool {
	for _, k := range []string{LabelRelay, ipalloc.LabelSlot, ipalloc.LabelSlotGeneration} {
		if a.Labels[k] != b.Labels[k] {
			return false
		}
	}
	return true
}

// tunnelLabels merges the agent labels with the identity labels of the relay.
func (p *TunnelPublisher) tunnelLabels(conn Connection, networkName, agentName string, slot ipalloc.Slot) map[string]string {
	labels := make(map[string]string, len(conn.Labels())+6)
	for k, v := range conn.Labels() {
		labels[k] = v
	}
	labels[vpcv1alpha1.LabelNetwork] = networkName
	labels[vpcv1alpha1.LabelTunnelName] = agentName
	labels[LabelRelay] = p.relayName
	labels[ipalloc.LabelSlot] = ipalloc.SlotLabelValue(slot)
	labels[ipalloc.LabelSlotGeneration] = strconv.FormatUint(slot.Generation, 10)
	if inst := conn.AgentInstance(); inst != "" {
		labels[vpcv1alpha1.LabelAgentInstance] = labelValue(inst)
	}
	return labels
}

// labelValue makes a valid label value from an agent string. A long value is
// cut to 32 chars; a value with bad characters becomes a hash.
func labelValue(v string) string {
	if len(validation.IsValidLabelValue(v)) == 0 {
		return v
	}
	if len(v) > validation.LabelValueMaxLength {
		if t := v[:32]; len(validation.IsValidLabelValue(t)) == 0 {
			return t
		}
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:32]
}

// errDeletePending means the Tunnel still exists after Delete, usually because
// its finalizers have not run yet.
var errDeletePending = errors.New("tunnel deletion is still pending")

// deleteTunnel deletes the connection's Tunnel object, tolerating a concurrent
// delete (orphan GC or drain may race the disconnect).
func (p *TunnelPublisher) deleteTunnel(ctx context.Context, id string) error {
	t := &vpcv1alpha1.Tunnel{ObjectMeta: metav1.ObjectMeta{Name: id}}
	if err := p.client.Delete(ctx, t); err != nil {
		return client.IgnoreNotFound(err)
	}
	var remaining vpcv1alpha1.Tunnel
	if err := p.client.Get(ctx, client.ObjectKey{Name: id}, &remaining); err != nil {
		return client.IgnoreNotFound(err)
	}
	return errDeletePending
}

// syncTunnel makes one apiserver attempt for a Tunnel: delete for a closed
// connection, else create when create is true.
func (p *TunnelPublisher) syncTunnel(ctx context.Context, id string, create bool) error {
	p.mu.Lock()
	st := p.tunnels[id]
	if st == nil || st.busy {
		p.mu.Unlock()
		return nil
	}
	var rec *connAlloc
	switch {
	case st.needsDelete():
		rec = st.written
	case create && st.needsCreate() && p.slots.Contains(st.live.alloc):
		// Recorded before the call: a create that fails can still exist.
		rec = st.live
		st.written = rec
	default:
		p.mu.Unlock()
		return nil
	}
	write := rec == st.live
	st.busy = true
	p.mu.Unlock()

	var err error
	if write {
		err = p.createTunnel(ctx, rec.tunnel)
	} else {
		err = p.deleteTunnel(ctx, id)
	}

	p.mu.Lock()
	st.busy = false
	if err != nil {
		st.attempts++
		st.retryAt = time.Now().Add(syncRetryDelay(st.attempts))
		p.mu.Unlock()
		if !write {
			metrics.TunnelCleanupRetries.Inc()
		}
		return err
	}
	if st.attempts > 0 {
		// The apiserver answers again, so the other writes that wait for a retry go now.
		if n := p.clearRetries(st); n > 0 {
			// This runs after the return paths below release mu.
			defer func() {
				slog.Info("Retrying waiting Tunnel writes after a write succeeded", slog.Int("retried", n))
				p.wakeWorker()
			}()
		}
	}
	st.attempts = 0
	st.retryAt = time.Time{}
	if write {
		rec.published = true
		if !st.needsDelete() && !st.needsCreate() {
			st.pendingSince = time.Time{}
		}
		p.mu.Unlock()
		slog.Debug("Published Tunnel", slog.String("connID", id))
		return nil
	}
	st.written = nil
	p.release(rec)
	if st.live == nil {
		delete(p.tunnels, id)
	} else if !st.needsCreate() {
		st.pendingSince = time.Time{}
	}
	p.mu.Unlock()

	metrics.TunnelCleanupPending.Dec()
	// A new connection with this ID can publish now.
	p.wakeWorker()
	return nil
}

// clearRetries makes the other idle retries due now and returns their count. It
// keeps attempts, so a write that fails again waits longer. The caller holds mu.
func (p *TunnelPublisher) clearRetries(except *tunnelState) int {
	n := 0
	for _, st := range p.tunnels {
		if st == except || st.busy || st.retryAt.IsZero() {
			continue
		}
		st.retryAt = time.Time{}
		n++
	}
	return n
}

func syncRetryDelay(attempt int) time.Duration {
	d := time.Second
	for i := 1; i < attempt && d < syncRetryCap; i++ {
		d *= 2
	}
	if d > syncRetryCap {
		return syncRetryCap
	}
	return d
}

func (p *TunnelPublisher) wakeWorker() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// run writes Tunnel changes until ctx ends. It returns after the writes in
// flight end.
func (p *TunnelPublisher) run(ctx context.Context) {
	defer close(p.workerDone)
	var syncs sync.WaitGroup
	defer syncs.Wait()
	ticker := time.NewTicker(syncScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		case <-ticker.C:
		}
		p.syncDue(ctx, true, &syncs)
	}
}

// syncDue starts one attempt for each due Tunnel, at most syncParallelism at a
// time, and reports the write backlog. Creates are skipped when create is false.
func (p *TunnelPublisher) syncDue(ctx context.Context, create bool, syncs *sync.WaitGroup) {
	now := time.Now()
	p.mu.Lock()
	create = create && !p.holdCreates
	ids := make([]string, 0)
	creates := 0
	var oldest time.Time
	for id, st := range p.tunnels {
		needsCreate := st.needsCreate()
		if !st.needsDelete() && !needsCreate {
			st.pendingSince = time.Time{}
			continue
		}
		if needsCreate {
			creates++
		}
		st.markPending(now)
		if oldest.IsZero() || st.pendingSince.Before(oldest) {
			oldest = st.pendingSince
		}
		if st.busy || st.retryAt.After(now) {
			continue
		}
		if st.needsDelete() || (create && needsCreate) {
			ids = append(ids, id)
		}
	}
	p.mu.Unlock()
	metrics.SetTunnelBacklog(p, creates, oldest)

	for _, id := range ids {
		select {
		case p.syncSlots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		syncs.Add(1)
		go func() {
			defer func() {
				<-p.syncSlots
				syncs.Done()
			}()
			opCtx, cancel := context.WithTimeout(ctx, syncTimeout)
			defer cancel()
			switch err := p.syncTunnel(opCtx, id, create); {
			case err == nil || ctx.Err() != nil:
			case errors.Is(err, errDeletePending):
				slog.Debug("Tunnel delete waits for finalizers; retrying", slog.String("connID", id))
			default:
				slog.Warn("Failed to write Tunnel; retrying",
					slog.String("connID", id), slog.Any("error", err))
			}
		}()
	}
}

func sameSlotGeneration(a, b ipalloc.Slot) bool {
	return a.Network == b.Network && a.ID == b.ID && a.Generation == b.Generation
}

func (p *TunnelPublisher) connectionIDsForNetwork(network tunnet.NetworkID) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for id, st := range p.tunnels {
		if st.live != nil && st.live.slot.Network == network {
			ids = append(ids, id)
		}
	}
	return ids
}

// ReleaseAll stops the worker, returns all slots, then deletes the pending
// Tunnels. Callers must disconnect every connection first.
func (p *TunnelPublisher) ReleaseAll(ctx context.Context) error {
	p.stopOnce.Do(p.stopWorker)
	select {
	case <-p.workerDone:
	case <-ctx.Done():
	}
	defer metrics.DeleteTunnelBacklog(p)
	err := p.slots.ReleaseAll(ctx)
	// A dead ctx would fail every pending delete at once; leave them.
	if ctx.Err() != nil || !p.hasPendingDeletes() {
		return err
	}
	delErr := p.deleteAllTunnels(ctx)
	if delErr == nil {
		p.mu.Lock()
		for id, st := range p.tunnels {
			if st.needsDelete() {
				p.release(st.written)
				st.written = nil
				metrics.TunnelCleanupPending.Dec()
			}
			if st.live == nil {
				delete(p.tunnels, id)
			}
		}
		p.mu.Unlock()
		return err
	}
	slog.Debug("Bulk Tunnel delete failed; deleting one at a time", slog.Any("error", delErr))
	p.mu.Lock()
	for _, st := range p.tunnels {
		st.retryAt = time.Time{}
	}
	p.mu.Unlock()
	var syncs sync.WaitGroup
	p.syncDue(ctx, false, &syncs)
	syncs.Wait()
	return err
}

func (p *TunnelPublisher) hasPendingDeletes() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, st := range p.tunnels {
		if st.needsDelete() {
			return true
		}
	}
	return false
}

// deleteAllTunnels deletes every Tunnel of this relay in one request.
func (p *TunnelPublisher) deleteAllTunnels(ctx context.Context) error {
	return p.client.DeleteAllOf(ctx, &vpcv1alpha1.Tunnel{}, client.MatchingLabels{LabelRelay: p.relayName})
}

// Resync deletes this relay's Tunnels that no connection uses and creates the
// missing ones. Call it at boot and when the apiserver is back.
func (p *TunnelPublisher) Resync(ctx context.Context) error {
	p.resyncMu.Lock()
	defer p.resyncMu.Unlock()
	p.mu.Lock()
	idle := len(p.tunnels) == 0
	p.holdCreates = idle
	p.mu.Unlock()
	if idle {
		// No connection here has a Tunnel, so all of this relay's Tunnels go.
		err := p.deleteAllTunnels(ctx)
		p.mu.Lock()
		p.holdCreates = false
		p.mu.Unlock()
		p.wakeWorker()
		if err == nil {
			return nil
		}
		slog.Debug("Bulk Tunnel delete failed; listing Tunnels", slog.Any("error", err))
	}

	var list vpcv1alpha1.TunnelList
	if err := p.client.List(ctx, &list, client.MatchingLabels{LabelRelay: p.relayName}); err != nil {
		return fmt.Errorf("failed to list Tunnels: %w", err)
	}
	present := make(map[string]bool, len(list.Items))
	now := time.Now()
	stale := 0
	p.mu.Lock()
	for i := range list.Items {
		id := list.Items[i].Name
		present[id] = true
		if p.tunnels[id] == nil {
			p.tunnels[id] = &tunnelState{written: staleAlloc(), pendingSince: now}
			stale++
		}
	}
	missing, retried := 0, 0
	for id, st := range p.tunnels {
		if st.busy {
			continue
		}
		// A create in flight can be missing from the list.
		if st.live != nil && st.live.published && !present[id] {
			st.live.published = false
			st.markPending(now)
			missing++
		}
		// The apiserver answers again, so the writes that wait for a retry go now.
		if !st.retryAt.IsZero() {
			st.retryAt, st.attempts = time.Time{}, 0
			retried++
		}
	}
	p.mu.Unlock()
	metrics.TunnelCleanupPending.Add(float64(stale))
	if stale > 0 || missing > 0 || retried > 0 {
		slog.Info("Syncing Tunnels with the apiserver",
			slog.Int("stale", stale), slog.Int("missing", missing), slog.Int("retried", retried))
		p.wakeWorker()
	}
	return nil
}

// prefixesToStrings renders a slice of prefixes as CIDR strings, returning nil
// for an empty slice so the Tunnel status omits the field.
func prefixesToStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out
}
