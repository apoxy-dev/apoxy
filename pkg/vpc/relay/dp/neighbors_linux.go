// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// nudValid are the neighbor states that have a MAC (NUD_VALID of the kernel).
const nudValid = unix.NUD_PERMANENT | unix.NUD_NOARP | unix.NUD_REACHABLE | unix.NUD_PROBE | unix.NUD_STALE | unix.NUD_DELAY

// kernelNeighbors is the kernel neighbor table of one link, for Shared mode. The follower writes
// the table, and the asker asks the kernel to resolve the hops that have no MAC.
type kernelNeighbors struct {
	link int             // The link index, in ns.
	ns   netns.NsHandle  // The netns of the thread that opened the table.
	h    *netlink.Handle // A netlink handle in ns, for the lists and the asks.

	mu      sync.RWMutex
	entries map[netip.Addr]tcpip.LinkAddress // The kernel entries of the link that have a MAC.

	asks chan netip.Addr // Hops with no MAC, to the asker. A full channel drops the hop.
	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

// neighborSub is one subscription to the neighbor updates of the kernel.
type neighborSub struct {
	updates chan netlink.NeighUpdate
	stop    chan struct{}
	errs    chan error // The first error of the subscription.
}

// end stops s and reads its updates until the library closes the channel: the library closes its
// socket only when stop closes, and its send to the channel waits.
func (s neighborSub) end() {
	close(s.stop)
	for range s.updates {
	}
}

// openKernelNeighbors follows the kernel neighbor table of the link with index link, in the netns
// of the calling thread. The table is full when it returns.
func openKernelNeighbors(link int) (*kernelNeighbors, error) {
	ns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get the netns of the relay interface: %w", err)
	}
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		ns.Close()
		return nil, fmt.Errorf("failed to open netlink in the netns of the relay interface: %w", err)
	}
	k := &kernelNeighbors{link: link, ns: ns, h: h, asks: make(chan netip.Addr, 64), done: make(chan struct{})}
	sub, err := k.subscribe()
	if err != nil {
		h.Close()
		ns.Close()
		return nil, err
	}
	k.wg.Go(func() { k.follow(sub) })
	k.wg.Go(k.ask)
	return k, nil
}

// subscribe subscribes to the neighbor updates, then reads the table of the link into entries. On
// an error it stops the subscription.
func (k *kernelNeighbors) subscribe() (neighborSub, error) {
	s := neighborSub{updates: make(chan netlink.NeighUpdate, 256), stop: make(chan struct{}), errs: make(chan error, 1)}
	err := netlink.NeighSubscribeWithOptions(s.updates, s.stop, netlink.NeighSubscribeOptions{
		Namespace: &k.ns,
		ErrorCallback: func(err error) {
			select {
			case s.errs <- err:
			default:
			}
		},
	})
	if err != nil {
		close(s.stop)
		return neighborSub{}, fmt.Errorf("failed to follow the kernel neighbor table: %w", err)
	}
	entries := map[netip.Addr]tcpip.LinkAddress{}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		list, err := k.h.NeighList(k.link, family)
		if err != nil {
			s.end()
			return neighborSub{}, fmt.Errorf("failed to read the kernel neighbor table: %w", err)
		}
		for _, n := range list {
			k.apply(entries, n, true)
		}
	}
	k.mu.Lock()
	k.entries = entries
	k.mu.Unlock()
	return s, nil
}

// apply writes the kernel entry n to entries: its MAC when add is true and the entry has one, else
// no entry. It ignores the entries of other links and proxy entries.
func (k *kernelNeighbors) apply(entries map[netip.Addr]tcpip.LinkAddress, n netlink.Neigh, add bool) {
	if n.LinkIndex != k.link || n.Flags&netlink.NTF_PROXY != 0 {
		return
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return
	}
	a = a.Unmap()
	if add && n.State&nudValid != 0 && len(n.HardwareAddr) == 6 {
		entries[a] = tcpip.LinkAddress(n.HardwareAddr)
	} else {
		delete(entries, a)
	}
}

// follow applies the updates of sub until close. After a receive error (for example ENOBUFS) the
// library closes the channel, and follow subscribes and reads the table again.
func (k *kernelNeighbors) follow(sub neighborSub) {
	for {
		select {
		case <-k.done:
			sub.end()
			return
		case u, ok := <-sub.updates:
			if ok {
				k.mu.Lock()
				k.apply(k.entries, u.Neigh, u.Type == unix.RTM_NEWNEIGH)
				k.mu.Unlock()
				continue
			}
			var err error
			select {
			case err = <-sub.errs:
			default:
			}
			sub.end()
			slog.Warn("Lost kernel neighbor updates; reading the table again", "link", k.link, "error", err)
			if sub, ok = k.resubscribe(); !ok {
				return
			}
		}
	}
}

// resubscribe subscribes again each 100 ms until it works. It returns false when close stops it.
func (k *kernelNeighbors) resubscribe() (neighborSub, bool) {
	for {
		select {
		case <-k.done:
			return neighborSub{}, false
		case <-time.After(100 * time.Millisecond):
		}
		sub, err := k.subscribe()
		if err == nil {
			return sub, true
		}
		slog.Warn("Failed to read the kernel neighbor table again", "link", k.link, "error", err)
	}
}

// neighbor returns the MAC of hop from the table. A miss gives hop to the asker and returns false.
func (k *kernelNeighbors) neighbor(hop netip.Addr) (tcpip.LinkAddress, bool) {
	if !hop.IsValid() {
		return "", false
	}
	hop = hop.WithZone("") // The kernel entries have no zone; a gateway can have one.
	k.mu.RLock()
	mac, ok := k.entries[hop]
	k.mu.RUnlock()
	if ok {
		return mac, true
	}
	select {
	case k.asks <- hop:
	default:
	}
	return "", false
}

// ask asks the kernel to resolve each hop of asks, at most once in each hopTTL for a hop, until
// close.
func (k *kernelNeighbors) ask() {
	last := map[netip.Addr]time.Time{}
	for {
		select {
		case <-k.done:
			return
		case hop := <-k.asks:
			now := time.Now()
			if at, ok := last[hop]; ok && now.Sub(at) < hopTTL {
				continue
			}
			if len(last) >= 1024 {
				clear(last)
			}
			last[hop] = now
			if err := k.resolve(hop); err != nil {
				slog.Warn("Failed to ask the kernel to resolve a next hop", "link", k.link, "hop", hop, "error", err)
			}
		}
	}
}

// resolve asks the kernel to resolve hop, from the kernel entry of hop now. It does not write an
// entry that has a MAC, because NTF_USE clears NUD_PERMANENT.
func (k *kernelNeighbors) resolve(hop netip.Addr) error {
	family := netlink.FAMILY_V4
	if hop.Is6() {
		family = netlink.FAMILY_V6
	}
	list, err := k.h.NeighList(k.link, family)
	if err != nil {
		return err
	}
	n := netlink.Neigh{LinkIndex: k.link, Family: family, IP: hop.AsSlice(), Flags: netlink.NTF_USE}
	for _, e := range list {
		if !e.IP.Equal(n.IP) || e.Flags&netlink.NTF_PROXY != 0 {
			continue
		}
		switch {
		case e.State&(nudValid|unix.NUD_INCOMPLETE) != 0:
			return nil // It has a MAC, or the kernel resolves it now.
		case e.Flags&netlink.NTF_EXT_LEARNED != 0 || e.FlagsExt&netlink.NTF_EXT_MANAGED != 0:
			return nil // A daemon owns the entry, and a write clears these flags.
		}
		// FAILED or NONE: the kernel keeps the state and starts a resolution.
		return k.h.NeighSet(&n)
	}
	// No entry: the kernel makes one and resolves it. EEXIST: the entry came after the list, and
	// the kernel did not change it.
	if err := k.h.NeighAdd(&n); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

// close stops the follower and the asker and waits for them.
func (k *kernelNeighbors) close() {
	k.once.Do(func() {
		close(k.done)
		k.wg.Wait()
		k.h.Close()
		k.ns.Close()
	})
}
