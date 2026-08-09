package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// LabelRelay is stamped by the relay on every Tunnel with its own name, so the
// relay-lease-gone orphan GC (and `kubectl get tunnels -l vpc.apoxy.dev/relay=x`)
// can select a relay's connections.
const LabelRelay = "vpc.apoxy.dev/relay"

const (
	cleanupScanInterval = time.Second
	cleanupRetryCap     = 30 * time.Second
)

// vniAllocator is the subset of the relay-local VNI allocator the publisher
// needs; satisfied by *vni.VNIAllocator. Kept as an interface so tests can
// substitute a deterministic allocator.
type vniAllocator interface {
	Allocate() (uint, error)
	Release(vni uint)
}

// TunnelPublisher owns the relay side of a connection's control-plane presence.
// It is wired to Relay.SetOnConnect/SetOnDisconnect and, on connect, allocates
// the connection's overlay addresses in-process from a leased slot (§2.8)
// plus a relay-local VNI (§2.5), assigns them onto the connection synchronously,
// and creates the single-writer Tunnel object (§2.4). On disconnect it deletes
// the Tunnel and returns the addresses and VNI to their pools. It makes zero
// apiserver round-trips for addressing; the one write is the Tunnel object.
//
// Network name -> NetworkID resolution is fed by the relay-side VPCNetwork
// watcher via SetNetworkID; a connect to an unresolved network fails until the
// network is provisioned and observed.
type TunnelPublisher struct {
	client    client.Client
	relayName string
	relay     Relay
	slots     *slotAllocator
	vnis      vniAllocator

	mu       sync.Mutex
	networks map[string]tunnet.NetworkID // VPCNetwork name -> NetworkID
	conns    map[string]*connAlloc       // connection ID -> allocation record

	cleanupWake chan struct{}
	cleanupStop chan struct{}
	cleanupDone chan struct{}
	stopOnce    sync.Once
}

// connAlloc records what a connection was assigned so disconnect can release it.
type connAlloc struct {
	alloc *ipalloc.ConnAllocator
	v6    netip.Prefix
	v4    netip.Prefix
	vni   uint
	slot  ipalloc.Slot

	pending         bool
	cleaning        bool
	attempts        int
	retryAt         time.Time
	cleanupComplete chan struct{}
}

// NewTunnelPublisher creates a TunnelPublisher and wires it to the relay's
// connect/disconnect callbacks.
func NewTunnelPublisher(c client.Client, relay Relay, leaser ipalloc.SlotLeaser, vnis vniAllocator) *TunnelPublisher {
	p := &TunnelPublisher{
		client:      c,
		relayName:   relay.Name(),
		relay:       relay,
		slots:       newSlotAllocator(leaser),
		vnis:        vnis,
		networks:    make(map[string]tunnet.NetworkID),
		conns:       make(map[string]*connAlloc),
		cleanupWake: make(chan struct{}, 1),
		cleanupStop: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	relay.SetOnConnect(p.OnConnect)
	relay.SetOnDisconnect(p.OnDisconnect)
	go p.cleanupLoop()
	return p
}

// SetNetworkID records the NetworkID a VPCNetwork name resolves to. Fed by the
// relay-side VPCNetwork watcher as networks are observed.
func (p *TunnelPublisher) SetNetworkID(name string, id tunnet.NetworkID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.networks[name] = id
}

// RemoveNetwork forgets a deleted VPCNetwork: connects to it fail closed again
// and every slot leased for it is returned, so its identifiers stop being
// renewed against a network that no longer exists.
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

// InvalidateSlot drops a slot the leaser lost so no new connections allocate
// from it. Wired to the leaser's slot-lost notification where one exists.
func (p *TunnelPublisher) InvalidateSlot(s ipalloc.Slot) {
	p.mu.Lock()
	p.slots.InvalidateSlot(s)
	ids := make([]string, 0)
	for id, rec := range p.conns {
		if sameSlotGeneration(rec.slot, s) {
			ids = append(ids, id)
		}
	}
	p.mu.Unlock()
	metrics.TunnelSlotLosses.Inc()
	for _, id := range ids {
		p.relay.DisconnectConnection(id)
	}
}

// OnConnect allocates addresses + a VNI for the connection, assigns them, and
// creates the Tunnel object. It is called synchronously from handleConnect.
func (p *TunnelPublisher) OnConnect(ctx context.Context, tunnelName, agentName string, conn Connection) error {
	networkName := conn.Network()

	if err := p.waitForPreviousCleanup(ctx, conn.ID()); err != nil {
		return err
	}

	p.mu.Lock()
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

	// Program the router with the primary (IPv6 /96) address, then install the
	// VNI (which derives its allowed routes from the overlay address).
	if err := conn.SetOverlayAddress(v6.String()); err != nil {
		p.releaseAll(alloc, v6, v4, vniID)
		return fmt.Errorf("failed to set overlay address: %w", err)
	}
	// From here on the router holds state for v6: failures must NOT release
	// the allocation directly — a concurrent connect would be handed the same
	// /96 while its route is still installed and fail with EEXIST (2026-08-03
	// incident). deferRelease parks the allocation under the connection ID so
	// the relay's teardown (conn.Close, then OnDisconnect) releases it only
	// after the router state is gone.
	if err := conn.SetVNI(ctx, vniID); err != nil {
		p.deferRelease(conn.ID(), alloc, v6, v4, vniID)
		return fmt.Errorf("failed to set VNI: %w", err)
	}

	addresses := []string{v6.String()}
	if v4.IsValid() {
		addresses = append(addresses, v4.String())
	}
	if err := conn.SetAddresses(addresses); err != nil {
		// The /32 is best-effort (§2.4): drop it and retry v6-only rather than
		// refuse the tunnel over the weaker family.
		if !v4.IsValid() {
			p.deferRelease(conn.ID(), alloc, v6, v4, vniID)
			return fmt.Errorf("failed to set overlay addresses: %w", err)
		}
		slog.Warn("Failed to program the IPv4 overlay address, continuing without v4",
			slog.String("connID", conn.ID()),
			slog.String("v4", v4.String()),
			slog.Any("error", err))
		p.slots.Release(alloc, netip.Prefix{}, v4)
		v4 = netip.Prefix{}
		addresses = addresses[:1]
		if err := conn.SetAddresses(addresses); err != nil {
			p.deferRelease(conn.ID(), alloc, v6, v4, vniID)
			return fmt.Errorf("failed to set overlay addresses: %w", err)
		}
	}

	if err := p.createTunnel(ctx, conn, networkName, agentName, addresses, slot); err != nil {
		p.deferRelease(conn.ID(), alloc, v6, v4, vniID)
		return fmt.Errorf("failed to create Tunnel object: %w", err)
	}

	rec := &connAlloc{alloc: alloc, v6: v6, v4: v4, vni: vniID, slot: slot}
	p.mu.Lock()
	slotHeld := p.slots.Contains(alloc)
	currentNetID, networkExists := p.networks[networkName]
	p.conns[conn.ID()] = rec
	p.mu.Unlock()
	if !slotHeld {
		return fmt.Errorf("overlay slot %s generation %d was lost during connection setup", ipalloc.SlotLabelValue(slot), slot.Generation)
	}
	if !networkExists || currentNetID != netID {
		return fmt.Errorf("network %q was removed during connection setup", networkName)
	}

	slog.Info("Published tunnel connection",
		slog.String("connID", conn.ID()),
		slog.String("network", networkName),
		slog.String("agent", agentName),
		slog.String("v6", v6.String()))
	return nil
}

// OnDisconnect deletes the connection's Tunnel object and returns its addresses
// and VNI only after the deletion is confirmed. It is idempotent: a connection
// with no allocation record still has its Tunnel object deleted by ID.
func (p *TunnelPublisher) OnDisconnect(ctx context.Context, agentName, id string) error {
	p.mu.Lock()
	rec, ok := p.conns[id]
	if !ok {
		rec = &connAlloc{}
		p.conns[id] = rec
	}
	if !rec.pending {
		rec.pending = true
		rec.cleanupComplete = make(chan struct{})
		metrics.TunnelCleanupPending.Inc()
	}
	p.mu.Unlock()

	// The retry worker owns API I/O. This keeps connection teardown prompt even
	// when the project apiserver is unavailable and makes retries independent
	// of the request or QUIC session context that triggered the disconnect.
	p.wakeCleanup()
	return nil
}

// waitForPreviousCleanup keeps a replacement connection in the same request
// until the prior Tunnel with its connection ID is gone. The old allocation
// stays quarantined until deletion is confirmed.
func (p *TunnelPublisher) waitForPreviousCleanup(ctx context.Context, id string) error {
	p.mu.Lock()
	rec, ok := p.conns[id]
	if !ok {
		p.mu.Unlock()
		return nil
	}
	if !rec.pending {
		p.mu.Unlock()
		return fmt.Errorf("connection ID %q is already active", id)
	}
	rec.retryAt = time.Time{}
	cleanupComplete := rec.cleanupComplete
	p.mu.Unlock()

	p.wakeCleanup()
	select {
	case <-cleanupComplete:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("failed to wait for previous connection cleanup: %w", ctx.Err())
	}
}

// releaseAll returns a connection's addresses and VNI to their pools.
func (p *TunnelPublisher) releaseAll(alloc *ipalloc.ConnAllocator, v6, v4 netip.Prefix, vniID uint) {
	p.slots.Release(alloc, v6, v4)
	p.vnis.Release(vniID)
}

// deferRelease parks a failed connection's allocation under its ID so
// OnDisconnect — which the relay's teardown runs only after conn.Close has
// unprogrammed the router — performs the release. Releasing earlier would let
// a concurrent connect allocate the same /96 while its route is still
// installed.
func (p *TunnelPublisher) deferRelease(id string, alloc *ipalloc.ConnAllocator, v6, v4 netip.Prefix, vniID uint) {
	p.mu.Lock()
	p.conns[id] = &connAlloc{alloc: alloc, v6: v6, v4: v4, vni: vniID, slot: alloc.Slot()}
	p.mu.Unlock()
}

// createTunnel writes the single-writer Tunnel object complete: spec + identity
// labels at create, then addresses + advertised routes via the status
// subresource. It is never patched in steady state (§2.4).
func (p *TunnelPublisher) createTunnel(ctx context.Context, conn Connection, networkName, agentName string, addresses []string, slot ipalloc.Slot) error {
	t := &vpcv1alpha1.Tunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name:   conn.ID(),
			Labels: p.tunnelLabels(conn, networkName, agentName, slot),
		},
		Spec: vpcv1alpha1.TunnelSpec{
			NetworkRef: vpcv1alpha1.VPCNetworkRef{Name: networkName},
			RelayRef:   vpcv1alpha1.RelayRef{Name: p.relayName},
		},
	}
	if err := p.client.Create(ctx, t); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	t.Status.Addresses = addresses
	t.Status.AdvertisedRoutes = prefixesToStrings(conn.AdvertisedRoutes())
	if err := p.client.Status().Update(ctx, t); err != nil {
		// Roll back the create so a half-written Tunnel does not linger.
		_ = p.client.Delete(ctx, t)
		return err
	}
	return nil
}

// tunnelLabels merges the agent-declared labels with the relay-stamped identity
// labels used by VPCService selection and orphan GC.
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

// labelValue coerces an agent-declared string into a legal Kubernetes label
// value. Agents declare their instance ID themselves — a pre-truncation
// containerized agent reports its full 64-hex container ID, one character
// over the 63-char label limit — and an invalid value must not fail Tunnel
// creation (which would refuse the connection entirely). An over-long but
// otherwise clean value is truncated to 32 chars, the SAME derivation current
// agents apply at the source (metrics.AgentProcessID), so old and new agents
// converge on one label form and it stays a greppable prefix of the raw
// metric label and the container ID. Only a value that is invalid for other
// reasons (illegal characters) is replaced by a truncated hash: stable per
// input, so identity is preserved under a derived name.
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
	return fmt.Errorf("tunnel deletion is still pending")
}

// tryCleanup makes one deletion attempt. The allocation stays quarantined on
// failure and is released exactly once after Delete or NotFound confirms that
// the stale Tunnel can no longer advertise it.
func (p *TunnelPublisher) tryCleanup(ctx context.Context, id string) error {
	p.mu.Lock()
	rec, ok := p.conns[id]
	if !ok || !rec.pending || rec.cleaning {
		p.mu.Unlock()
		return nil
	}
	rec.cleaning = true
	p.mu.Unlock()

	err := p.deleteTunnel(ctx, id)

	p.mu.Lock()
	current, stillCurrent := p.conns[id]
	if !stillCurrent || current != rec {
		p.mu.Unlock()
		return err
	}
	if err != nil {
		rec.cleaning = false
		rec.attempts++
		rec.retryAt = time.Now().Add(cleanupRetryDelay(rec.attempts))
		p.mu.Unlock()
		metrics.TunnelCleanupRetries.Inc()
		return err
	}
	delete(p.conns, id)
	p.mu.Unlock()

	metrics.TunnelCleanupPending.Dec()
	if rec.alloc != nil {
		p.releaseAll(rec.alloc, rec.v6, rec.v4, rec.vni)
	}
	close(rec.cleanupComplete)
	return nil
}

func cleanupRetryDelay(attempt int) time.Duration {
	d := time.Second
	for i := 1; i < attempt && d < cleanupRetryCap; i++ {
		d *= 2
	}
	if d > cleanupRetryCap {
		return cleanupRetryCap
	}
	return d
}

func (p *TunnelPublisher) wakeCleanup() {
	select {
	case p.cleanupWake <- struct{}{}:
	default:
	}
}

func (p *TunnelPublisher) cleanupLoop() {
	defer close(p.cleanupDone)
	ticker := time.NewTicker(cleanupScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.cleanupStop:
			return
		case <-p.cleanupWake:
			p.retryPending(context.Background())
		case <-ticker.C:
			p.retryPending(context.Background())
		}
	}
}

func (p *TunnelPublisher) retryPending(ctx context.Context) {
	now := time.Now()
	p.mu.Lock()
	ids := make([]string, 0, len(p.conns))
	for id, rec := range p.conns {
		if rec.pending && !rec.cleaning && !rec.retryAt.After(now) {
			ids = append(ids, id)
		}
	}
	p.mu.Unlock()

	for _, id := range ids {
		deleteCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := p.tryCleanup(deleteCtx, id)
		cancel()
		if err != nil {
			slog.Warn("Failed to delete Tunnel; retrying",
				slog.String("connID", id), slog.Any("error", err))
		}
	}
}

func sameSlotGeneration(a, b ipalloc.Slot) bool {
	return a.Network == b.Network && a.ID == b.ID && a.Generation == b.Generation
}

func (p *TunnelPublisher) connectionIDsForNetwork(network tunnet.NetworkID) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for id, rec := range p.conns {
		if rec.slot.Network == network {
			ids = append(ids, id)
		}
	}
	return ids
}

// ReleaseAll returns every leased slot to the leaser. Called at drain.
func (p *TunnelPublisher) ReleaseAll(ctx context.Context) {
	p.stopOnce.Do(func() { close(p.cleanupStop) })
	select {
	case <-p.cleanupDone:
	case <-ctx.Done():
	}
	p.retryPending(ctx)
	p.slots.ReleaseAll(ctx)
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
