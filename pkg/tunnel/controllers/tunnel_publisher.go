package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/ipalloc"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// LabelRelay is stamped by the relay on every Tunnel with its own name, so the
// relay-lease-gone orphan GC (and `kubectl get tunnels -l vpc.apoxy.dev/relay=x`)
// can select a relay's connections.
const LabelRelay = "vpc.apoxy.dev/relay"

// vniAllocator is the subset of the relay-local VNI allocator the publisher
// needs; satisfied by *vni.VNIAllocator. Kept as an interface so tests can
// substitute a deterministic allocator.
type vniAllocator interface {
	Allocate() (uint, error)
	Release(vni uint)
}

// TunnelPublisher owns the relay side of a connection's control-plane presence.
// It is wired to Relay.SetOnConnect/SetOnDisconnect and, on connect, allocates
// the connection's overlay addresses in-process from a leased /80 block (§2.8)
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
	blocks    *blockAllocator
	vnis      vniAllocator

	mu       sync.Mutex
	networks map[string]tunnet.NetworkID // VPCNetwork name -> NetworkID
	conns    map[string]*connAlloc       // connection ID -> allocation record
}

// connAlloc records what a connection was assigned so disconnect can release it.
type connAlloc struct {
	alloc *ipalloc.ConnAllocator
	v6    netip.Prefix
	v4    netip.Prefix
	vni   uint
}

// NewTunnelPublisher creates a TunnelPublisher and wires it to the relay's
// connect/disconnect callbacks.
func NewTunnelPublisher(c client.Client, relay Relay, leaser ipalloc.BlockLeaser, vnis vniAllocator) *TunnelPublisher {
	p := &TunnelPublisher{
		client:    c,
		relayName: relay.Name(),
		blocks:    newBlockAllocator(leaser),
		vnis:      vnis,
		networks:  make(map[string]tunnet.NetworkID),
		conns:     make(map[string]*connAlloc),
	}
	relay.SetOnConnect(p.OnConnect)
	relay.SetOnDisconnect(p.OnDisconnect)
	return p
}

// SetNetworkID records the NetworkID a VPCNetwork name resolves to. Fed by the
// relay-side VPCNetwork watcher as networks are observed.
func (p *TunnelPublisher) SetNetworkID(name string, id tunnet.NetworkID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.networks[name] = id
}

// OnConnect allocates addresses + a VNI for the connection, assigns them, and
// creates the Tunnel object. It is called synchronously from handleConnect.
func (p *TunnelPublisher) OnConnect(ctx context.Context, tunnelName, agentName string, conn Connection) error {
	networkName := conn.Network()

	p.mu.Lock()
	netID, ok := p.networks[networkName]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("network %q is not provisioned yet", networkName)
	}

	v6, v4, alloc, err := p.blocks.Allocate(ctx, netID)
	if err != nil {
		return fmt.Errorf("failed to allocate connection addresses: %w", err)
	}

	vniID, err := p.vnis.Allocate()
	if err != nil {
		p.blocks.Release(alloc, v6, v4)
		return fmt.Errorf("failed to allocate VNI: %w", err)
	}

	// Program the router with the primary (IPv6 /96) address, then install the
	// VNI (which derives its allowed routes from the overlay address).
	if err := conn.SetOverlayAddress(v6.String()); err != nil {
		p.releaseAll(alloc, v6, v4, vniID)
		return fmt.Errorf("failed to set overlay address: %w", err)
	}
	if err := conn.SetVNI(ctx, vniID); err != nil {
		p.releaseAll(alloc, v6, v4, vniID)
		return fmt.Errorf("failed to set VNI: %w", err)
	}

	addresses := []string{v6.String()}
	if v4.IsValid() {
		addresses = append(addresses, v4.String())
	}
	conn.SetAddresses(addresses)

	if err := p.createTunnel(ctx, conn, networkName, agentName, addresses); err != nil {
		p.releaseAll(alloc, v6, v4, vniID)
		return fmt.Errorf("failed to create Tunnel object: %w", err)
	}

	p.mu.Lock()
	p.conns[conn.ID()] = &connAlloc{alloc: alloc, v6: v6, v4: v4, vni: vniID}
	p.mu.Unlock()

	slog.Info("Published tunnel connection",
		slog.String("connID", conn.ID()),
		slog.String("network", networkName),
		slog.String("agent", agentName),
		slog.String("v6", v6.String()))
	return nil
}

// OnDisconnect deletes the connection's Tunnel object and returns its addresses
// and VNI to their pools. It is idempotent: a connection with no allocation
// record (e.g. an orphan from a prior relay incarnation) still has its Tunnel
// object deleted by ID.
func (p *TunnelPublisher) OnDisconnect(ctx context.Context, agentName, id string) error {
	p.mu.Lock()
	rec, ok := p.conns[id]
	delete(p.conns, id)
	p.mu.Unlock()

	// Release the in-process allocation before attempting the Tunnel delete: the
	// record is already gone from p.conns, so if the delete errors there is
	// nothing left to retry it, and a deferred release would permanently strand
	// the /96, /32, and VNI.
	if ok {
		p.releaseAll(rec.alloc, rec.v6, rec.v4, rec.vni)
	}

	return p.deleteTunnel(ctx, id)
}

// releaseAll returns a connection's addresses and VNI to their pools.
func (p *TunnelPublisher) releaseAll(alloc *ipalloc.ConnAllocator, v6, v4 netip.Prefix, vniID uint) {
	p.blocks.Release(alloc, v6, v4)
	p.vnis.Release(vniID)
}

// createTunnel writes the single-writer Tunnel object complete: spec + identity
// labels at create, then addresses + advertised routes via the status
// subresource. It is never patched in steady state (§2.4).
func (p *TunnelPublisher) createTunnel(ctx context.Context, conn Connection, networkName, agentName string, addresses []string) error {
	t := &vpcv1alpha1.Tunnel{
		ObjectMeta: metav1.ObjectMeta{
			Name:   conn.ID(),
			Labels: p.tunnelLabels(conn, networkName, agentName),
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
func (p *TunnelPublisher) tunnelLabels(conn Connection, networkName, agentName string) map[string]string {
	labels := make(map[string]string, len(conn.Labels())+4)
	for k, v := range conn.Labels() {
		labels[k] = v
	}
	labels[vpcv1alpha1.LabelNetwork] = networkName
	labels[vpcv1alpha1.LabelTunnelName] = agentName
	labels[LabelRelay] = p.relayName
	if inst := conn.AgentInstance(); inst != "" {
		labels[vpcv1alpha1.LabelAgentInstance] = inst
	}
	return labels
}

// deleteTunnel deletes the connection's Tunnel object, tolerating a concurrent
// delete (orphan GC or drain may race the disconnect).
func (p *TunnelPublisher) deleteTunnel(ctx context.Context, id string) error {
	t := &vpcv1alpha1.Tunnel{ObjectMeta: metav1.ObjectMeta{Name: id}}
	return client.IgnoreNotFound(p.client.Delete(ctx, t))
}

// ReleaseAll returns every leased block to the leaser. Called at drain.
func (p *TunnelPublisher) ReleaseAll(ctx context.Context) {
	p.blocks.ReleaseAll(ctx)
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
