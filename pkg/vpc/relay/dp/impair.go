// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type impair_key -type impair_value xdp ebpf/xdp.c

// impairPin is where the relay pins the impair map. Its directory must be on bpffs.
const impairPin = "/sys/fs/bpf/apoxy-relay/impair"

// Impairment is an entry of the impair map. Tests use it to drop and delay the packets between a
// UDP port of the relay and the peers in a prefix. In production the map is empty.
type Impairment struct {
	// Port is the UDP port of the relay: 443 or 1000.
	Port uint16
	// Peer is the prefix of the peers. An IPv6 prefix also matches IPv4 peers as ::ffff:a.b.c.d.
	Peer netip.Prefix
	// Drop is the probability, from 0 to 1, that the XDP program drops a received packet.
	Drop float64
	// Delay is the time that the send path holds a packet, plus a random value in ±Jitter.
	Delay, Jitter time.Duration
	// Dropped is the number of packets that the entry dropped.
	Dropped uint64
}

// Impair is the impair map of the relay.
type Impair struct {
	m *ebpf.Map
}

// OpenImpair opens the impair map. It makes and pins the map when the relay did not make it.
func OpenImpair() (*Impair, error) {
	m, err := openImpairMap()
	if err != nil {
		return nil, err
	}
	return &Impair{m: m}, nil
}

// Close closes the map. The map and its entries stay.
func (i *Impair) Close() error { return i.m.Close() }

// Set writes the entry of port and peer. delay and jitter have a resolution of 1µs. The dropped
// count of a new entry starts at 0.
func (i *Impair) Set(port uint16, peer netip.Prefix, drop float64, delay, jitter time.Duration) error {
	switch {
	case port != portQUIC && port != PortData:
		return fmt.Errorf("port %d is not a port of the relay (%d or %d)", port, portQUIC, PortData)
	case !peer.IsValid():
		return errors.New("the peer prefix is not valid")
	case !(drop >= 0 && drop <= 1):
		return fmt.Errorf("drop %v is not between 0 and 1", drop)
	}
	us := func(name string, d time.Duration) (uint32, error) {
		if d < 0 || d/time.Microsecond > math.MaxUint32 {
			return 0, fmt.Errorf("%s %v is out of range", name, d)
		}
		return uint32(d / time.Microsecond), nil
	}
	v := xdpImpairValue{Drop: uint64(math.Round(drop * (1 << 32)))}
	var err error
	if v.Delay, err = us("delay", delay); err != nil {
		return err
	}
	if v.Jitter, err = us("jitter", jitter); err != nil {
		return err
	}
	if err := i.m.Put(impairKey(port, peer), &v); err != nil {
		return fmt.Errorf("failed to write the impair entry: %w", err)
	}
	return nil
}

// Clear removes all entries.
func (i *Impair) Clear() error {
	var k xdpImpairKey
	for {
		err := i.m.NextKey(nil, &k)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read the impair map: %w", err)
		}
		if err := i.m.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to remove an impair entry: %w", err)
		}
	}
}

// Show returns all entries.
func (i *Impair) Show() ([]Impairment, error) { return impairments(i.m) }

// openImpairMap opens the pinned impair map, or makes and pins it.
func openImpairMap() (*ebpf.Map, error) {
	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("failed to load the relay XDP objects: %w", err)
	}
	ms := spec.Maps["impair"]
	ms.Pinning = ebpf.PinByName
	dir := filepath.Dir(impairPin)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to make the directory of the impair map (is bpffs mounted?): %w", err)
	}
	m, err := ebpf.NewMapWithOptions(ms, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		return nil, fmt.Errorf("failed to open the impair map at %s: %w", impairPin, err)
	}
	return m, nil
}

// impairKey is the LPM trie key of port and peer: the port, then the peer as 16 bytes.
func impairKey(port uint16, peer netip.Prefix) *xdpImpairKey {
	peer = peer.Masked()
	bits := peer.Bits()
	if peer.Addr().Is4() {
		bits += 96
	}
	k := &xdpImpairKey{Prefixlen: uint32(16 + bits), Addr: peer.Addr().As16()}
	binary.BigEndian.PutUint16(k.Port[:], port)
	return k
}

// impairments reads all entries of m.
func impairments(m *ebpf.Map) ([]Impairment, error) {
	var (
		out []Impairment
		k   xdpImpairKey
		v   xdpImpairValue
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		a, bits := netip.AddrFrom16(k.Addr), int(k.Prefixlen)-16
		if a.Is4In6() && bits >= 96 {
			a, bits = a.Unmap(), bits-96
		}
		out = append(out, Impairment{
			Port:    binary.BigEndian.Uint16(k.Port[:]),
			Peer:    netip.PrefixFrom(a, bits),
			Drop:    float64(v.Drop) / (1 << 32),
			Delay:   time.Duration(v.Delay) * time.Microsecond,
			Jitter:  time.Duration(v.Jitter) * time.Microsecond,
			Dropped: v.Dropped,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("failed to read the impair map: %w", err)
	}
	return out, nil
}

// delayTable is the copy of the impair map that the send path reads. It finds the longest
// prefix, as the LPM trie does.
type delayTable []delayEntry

type delayEntry struct {
	port          uint16
	peer          netip.Prefix // as 16 bytes, so that an IPv6 prefix matches mapped IPv4 peers
	delay, jitter time.Duration
}

// newDelayTable makes the table of the entries. It is nil when no entry delays a packet.
func newDelayTable(entries []Impairment) delayTable {
	var t delayTable
	delays := false
	for _, e := range entries {
		peer := e.Peer
		if peer.Addr().Is4() {
			peer = netip.PrefixFrom(netip.AddrFrom16(peer.Addr().As16()), peer.Bits()+96)
		}
		t = append(t, delayEntry{port: e.Port, peer: peer, delay: e.Delay, jitter: e.Jitter})
		delays = delays || e.Delay > 0 || e.Jitter > 0
	}
	if !delays {
		return nil
	}
	return t
}

// wait returns the time to hold a send from port to the peer a: the delay of the entry with the
// longest prefix, plus a random value in ±jitter.
func (t delayTable) wait(port uint16, a netip.Addr) time.Duration {
	a = netip.AddrFrom16(a.As16())
	best := -1
	for i, e := range t {
		if e.port == port && e.peer.Contains(a) && (best < 0 || e.peer.Bits() > t[best].peer.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return 0
	}
	e := t[best]
	w := e.delay
	if e.jitter > 0 {
		w += time.Duration(rand.Int64N(int64(2*e.jitter)+1)) - e.jitter
	}
	return max(w, 0)
}
