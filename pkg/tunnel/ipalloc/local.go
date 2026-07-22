package ipalloc

import (
	"context"
	"fmt"
	"sync"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// LocalBlockLeaser is the OSS/single-tenant BlockLeaser. It leases /80 blocks
// from the standalone process's own view of each network's /72 ULA — there is
// no infra tier, so blocks are backed by an in-process go-ipam per network and
// leases have no TTL (Renew is a no-op). The API is identical to the cloud
// infra-apiz implementation so the relay wiring is the same in both modes.
type LocalBlockLeaser struct {
	ctx context.Context

	mu   sync.Mutex
	nets map[tunnet.NetworkID]tunnet.IPAM
}

// NewLocalBlockLeaser returns a LocalBlockLeaser. ctx bounds the lifetime of
// the per-network go-ipam instances it lazily creates.
func NewLocalBlockLeaser(ctx context.Context) *LocalBlockLeaser {
	return &LocalBlockLeaser{
		ctx:  ctx,
		nets: make(map[tunnet.NetworkID]tunnet.IPAM),
	}
}

// ipamFor returns the /80-allocating IPAM for a network, creating it on first
// use. The IPAM is rooted at the network's /72 so it hands out /80 block
// children. Caller holds mu.
func (l *LocalBlockLeaser) ipamFor(network tunnet.NetworkID) (tunnet.IPAM, error) {
	if ipam, ok := l.nets[network]; ok {
		return ipam, nil
	}

	ula, err := tunnet.ULAFromPrefix(l.ctx, network72(network))
	if err != nil {
		return nil, fmt.Errorf("failed to root ULA at network /72: %w", err)
	}
	ipam, err := ula.IPAM(l.ctx, 80)
	if err != nil {
		return nil, fmt.Errorf("failed to create block IPAM: %w", err)
	}

	l.nets[network] = ipam
	return ipam, nil
}

// Lease reserves an unused /80 block of the network's /72.
func (l *LocalBlockLeaser) Lease(_ context.Context, network tunnet.NetworkID) (Block, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ipam, err := l.ipamFor(network)
	if err != nil {
		return Block{}, err
	}
	p, err := ipam.Allocate()
	if err != nil {
		return Block{}, fmt.Errorf("%w: %v", ErrNoBlocks, err)
	}
	return Block{Network: network, Index: blockIndex(p), Prefix: p}, nil
}

// Renew is a no-op: local leases have no TTL.
func (l *LocalBlockLeaser) Renew(_ context.Context, _ Block) error {
	return nil
}

// Release returns a block to the network's pool.
func (l *LocalBlockLeaser) Release(_ context.Context, b Block) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ipam, ok := l.nets[b.Network]
	if !ok {
		return nil
	}
	return ipam.Release(b.Prefix)
}
