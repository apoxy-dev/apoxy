// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	"golang.org/x/time/rate"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// trunkRevision is the first revision with trunk keys and the trunk probe.
	trunkRevision = 5
	// trunkRowsRevision is the first revision of a relay that takes the SPI rows
	// and the packets of the senders of another relay.
	trunkRowsRevision = 8
	// trunkBridgeRevision is the first revision of a relay that takes the clear
	// inner packets of the senders of another relay.
	trunkBridgeRevision = 9

	// trunkLanePSP is the SA lane for whole PSP packets of agents. It has no
	// replay window, because the agent that gets each packet has one.
	trunkLanePSP = 0
	// trunkLaneInner is the SA lane with a replay window, for clear inner
	// packets and for the messages of the relay itself.
	trunkLaneInner = 1
	trunkLanes     = 2

	// trunkPayload is the largest payload of a trunk packet, and so the
	// largest PSP packet of an agent that goes between two relays.
	trunkPayload = maxUDP - pspwire.Overhead
	// trunkMTU is the largest inner MTU of that PSP packet.
	trunkMTU = trunkPayload - pspwire.Overhead
	// trunkLimitedMTU is the inner MTU of a trunk with no full-size probe that
	// passed. It is the least MTU of a network.
	trunkLimitedMTU = vpcv1alpha1.DefaultMTU

	// trunkTagRelay is the tag of the messages of the relay itself. A session
	// has a tag from 1, so no packet of an agent has tag 0.
	trunkTagRelay = 0
	// The first byte of a message of the relay is its type.
	trunkMsgProbe = 0x01
	trunkMsgReply = 0x02
	// trunkProbeLen is the type byte and the ID of the probe run.
	trunkProbeLen = 1 + 8

	// A probe run has the numbers of the path probe of an agent: up to 3
	// packets 300 ms apart, and no answer in 1 s fails it.
	trunkProbeRounds   = 3
	trunkProbeInterval = 300 * time.Millisecond
	trunkProbeWait     = time.Second
	// trunkProbeRetry is the time from a failed run to the next run.
	trunkProbeRetry = 30 * time.Second
	// trunkKeysTimeout limits one TrunkKeys call.
	trunkKeysTimeout = 5 * time.Second
)

var (
	errTrunkEnded   = errors.New("trunk session ended")
	errTrunkRefused = errors.New("member refused the SPIs of each offer")
)

// trunkPath is the result of the full-size probe of a pair.
type trunkPath uint32

const (
	trunkPathUnknown trunkPath = iota // No run ended.
	trunkPathFull                     // The path carried a full-size packet.
	trunkPathLimited                  // The last run got no answer.
)

// trunk keeps the trunk SAs of this relay and each mesh member that is up, for
// the two directions. The two relays of a pair run the same code.
type trunk struct {
	m *Mesh
	r *Router

	// addrs has the pairs by member address, for the packet path.
	addrs atomic.Pointer[map[netip.AddrPort]*trunkPair]
	// names has the pairs by relay name, for the bridge.
	names atomic.Pointer[map[string]*trunkPair]

	// mu guards the fields below. Take it last: after Mesh.mu, after Router.mu
	// and after the lock of the presence.
	mu      sync.Mutex
	pairs   map[string]*trunkPair     // By relay name of the member.
	byRx    map[*keys.Peer]*trunkPair // Pair of each receive peer.
	members map[string]*trunkMember   // By relay name. Each has a row or carries rows.
}

// trunkMember is the place of one member for the SPI rows to it. A row keeps
// it, so the row stays when the trunk has no keys of the member for a time.
type trunkMember struct {
	name string
	// pair carries the packets of the rows now. It is nil with no keys of the
	// member, and for a member from before the row revision.
	pair atomic.Pointer[trunkPair]
	rows int // Rows of the router that keep it. trunk.mu guards it.
}

// trunkPair is the trunk state of this relay and one member.
type trunkPair struct {
	name    string
	addr    netip.AddrPort // Address of the relay socket of the member.
	udp     *net.UDPAddr   // The same address, for the sends.
	tx      *keys.TxPeer   // SAs of the member for packets to it.
	answers *rate.Limiter  // Limits the answers to the probes of the member.

	spis atomic.Pointer[[]trunkSPI] // Receive SAs, for the packet path.
	run  atomic.Pointer[trunkProbe] // Probe run that waits for its answer.
	path atomic.Uint32              // A trunkPath value.
	// bridges is set when the member takes the clear inner packets of senders.
	bridges atomic.Bool

	// trunk.mu guards the fields below.
	rx      *keys.Peer     // SAs of this relay for packets from the member, or nil.
	txFrom  *MeshSession   // Session that gave the SAs of tx last.
	sess    *trunkSession  // Key exchange on the newest session, or nil.
	pending []keys.Request // Rekeys that the member did not get.
	gone    bool           // The trunk removed the pair.
}

// trunkSPI is one receive SA of a pair.
type trunkSPI struct {
	spi  uint32
	lane int
	// sess is the only session that gave the SA to the member. It is nil for an
	// SA that the member did not get.
	sess *MeshSession
}

// trunkSession is the key exchange of a pair on one mesh session, and the
// SPIRows call of that session. trunk.mu guards its fields.
type trunkSession struct {
	s       *MeshSession
	wake    chan struct{} // Has room for 1: fresh or pending changed.
	ready   chan struct{} // Closed when the pair has keys in both directions.
	fresh   bool          // The member needs a new offer of all lanes.
	offered bool          // The member accepted an offer on this session.
	probing bool          // ready is closed.

	rows     map[rowKey]rowState // Last state of each row that the member must get.
	rowWake  chan struct{}       // Has room for 1: rows changed.
	rowsDone bool                // The SPIRows call failed, and the member gets no more rows.
}

// trunkProbe is one probe run.
type trunkProbe struct {
	id   [trunkProbeLen - 1]byte
	ok   chan struct{} // Closed at the first good answer.
	once sync.Once
}

// setTrunk makes m exchange trunk keys with each member at the trunk revision
// or later. Call it after PacketHandler of r and before Run.
func (m *Mesh) setTrunk(r *Router) {
	t := &trunk{
		m: m, r: r,
		pairs: map[string]*trunkPair{}, byRx: map[*keys.Peer]*trunkPair{}, members: map[string]*trunkMember{},
	}
	// A second call must not add the hooks again.
	if !m.trunk.CompareAndSwap(nil, t) {
		return
	}
	r.trunk.Store(t)
	m.OnSession(t.opened)
	m.OnChange(t.changed)
}

// mtu returns the largest inner MTU of an agent packet that the trunk to the
// member carries. It is 1280 until a full-size probe passes.
func (p *trunkPair) mtu() int {
	if trunkPath(p.path.Load()) == trunkPathFull {
		return trunkMTU
	}
	return trunkLimitedMTU
}

// sa returns the receive SA of the pair with spi. It reports false for
// another SPI: a member must not send with the SA of another member.
func (p *trunkPair) sa(spi uint32) (trunkSPI, bool) {
	if spis := p.spis.Load(); spis != nil {
		for _, sa := range *spis {
			if sa.spi == spi {
				return sa, true
			}
		}
	}
	return trunkSPI{}, false
}

// pair returns the pair of member name, or nil if the trunk has no keys of it.
func (t *trunk) pair(name string) *trunkPair {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pairs[name]
}

// from returns the pair of the member with the relay socket address src.
func (t *trunk) from(src netip.AddrPort) *trunkPair {
	if m := t.addrs.Load(); m != nil {
		return (*m)[src]
	}
	return nil
}

// bridgeTo returns the pair that carries clear inner packets to member name.
// It is nil with no pair, and for a member from before the bridge revision.
func (t *trunk) bridgeTo(name string) *trunkPair {
	if m := t.names.Load(); m != nil {
		if p := (*m)[name]; p != nil && p.bridges.Load() {
			return p
		}
	}
	return nil
}

// pairOf returns the pair of the member of s, and makes it if it is new. A
// member at a new address gets a new pair. t.mu must be held.
func (t *trunk) pairOf(br *bridge, s *MeshSession) *trunkPair {
	addr := addrPort(s.qc.RemoteAddr())
	p := t.pairs[s.name]
	if p != nil && p.addr == addr {
		return p
	}
	if p != nil {
		t.remove(p)
	}
	p = &trunkPair{
		name:    s.name,
		addr:    addr,
		udp:     net.UDPAddrFromAddrPort(addr),
		tx:      br.send.NewPeer(),
		answers: rate.NewLimiter(probeRate, probeRate),
	}
	t.pairs[p.name] = p
	t.index()
	return p
}

// index makes the tables of the packet path and of the bridge again. t.mu
// must be held.
func (t *trunk) index() {
	m := make(map[netip.AddrPort]*trunkPair, len(t.pairs))
	for _, p := range t.pairs {
		m[p.addr] = p
	}
	t.addrs.Store(&m)
	names := maps.Clone(t.pairs)
	t.names.Store(&names)
}

// remove deletes p and all its keys. t.mu must be held.
func (t *trunk) remove(p *trunkPair) {
	t.revokeRx(p)
	revokeTx(p.tx)
	p.gone = true
	if t.pairs[p.name] == p {
		delete(t.pairs, p.name)
		t.index()
	}
	if m := t.members[p.name]; m != nil {
		// The rows to the member stay, and their packets drop until it has keys again.
		m.pair.CompareAndSwap(p, nil)
		t.forget(m)
	}
}

// hold returns the place of member name for one more row of the router.
func (t *trunk) hold(name string) *trunkMember {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.members[name]
	if m == nil {
		m = &trunkMember{name: name}
		t.members[name] = m
	}
	m.rows++
	return m
}

// forget deletes the place m when no row keeps it and it carries no rows.
// t.mu must be held.
func (t *trunk) forget(m *trunkMember) {
	if m.rows == 0 && m.pair.Load() == nil {
		delete(t.members, m.name)
	}
}

// carry makes p the pair for the rows and the clear inner packets to its member,
// each if the session that gave its SAs last is at its revision. t.mu must be held.
func (t *trunk) carry(p *trunkPair) {
	rev := p.txFrom.Version().GetRevision()
	p.bridges.Store(rev >= trunkBridgeRevision)
	m := t.members[p.name]
	if rev < trunkRowsRevision {
		if m != nil {
			m.pair.CompareAndSwap(p, nil)
			t.forget(m)
		}
		return
	}
	if m == nil {
		m = &trunkMember{name: p.name}
		t.members[p.name] = m
	}
	m.pair.Store(p)
}

// revokeRx deletes the receive SAs of p and ends its key exchange. t.mu must
// be held.
func (t *trunk) revokeRx(p *trunkPair) {
	if p.rx != nil {
		p.rx.Revoke()
		delete(t.byRx, p.rx)
		p.rx = nil
	}
	p.spis.Store(nil)
	p.sess, p.pending = nil, nil
	p.path.Store(uint32(trunkPathUnknown))
}

// addSPIs adds the new receive SAs of p, which only s gives to the member.
// t.mu must be held.
func (t *trunk) addSPIs(p *trunkPair, sas []keys.SA, s *MeshSession) {
	var spis []trunkSPI
	if old := p.spis.Load(); old != nil {
		spis = slices.Clone(*old)
	}
	for _, sa := range sas {
		spis = append(spis, trunkSPI{sa.SPI, sa.Lane, s})
	}
	p.spis.Store(&spis)
}

// prune removes the SPIs of p whose SA is not in the receive table. t.mu must
// be held.
func (t *trunk) prune(br *bridge, p *trunkPair) {
	gone := func(sa trunkSPI) bool {
		_, ok := br.table.Stats(sa.spi)
		return !ok
	}
	if spis := p.spis.Load(); spis != nil && slices.ContainsFunc(*spis, gone) {
		live := slices.DeleteFunc(slices.Clone(*spis), gone)
		p.spis.Store(&live)
	}
}

// opened starts the key exchange with the member of the new session s. A
// member from before the trunk gets no call.
func (t *trunk) opened(s *MeshSession) {
	t.endRows(s)
	br := t.r.bridge.Load()
	if br == nil || s.Version().GetRevision() < trunkRevision {
		return
	}
	ts := &trunkSession{
		s: s, wake: make(chan struct{}, 1), ready: make(chan struct{}), fresh: true,
		rows: map[rowKey]rowState{}, rowWake: make(chan struct{}, 1),
	}
	ts.wake <- struct{}{}
	// A member from before the row revision gets no SPIRows call.
	rows := s.Version().GetRevision() >= trunkRowsRevision
	ts.rowsDone = !rows
	// The read lock keeps each row change out until ts has the rows of the
	// pair and gets the changes.
	t.r.mu.RLock()
	t.mu.Lock()
	p := t.pairOf(br, s)
	// The new offer replaces the rekeys that the member did not get.
	p.sess, p.pending = ts, nil
	if rows {
		t.r.liveRows(p, ts)
	}
	t.mu.Unlock()
	t.r.mu.RUnlock()
	t.m.wg.Go(func() { t.give(br, p, ts) })
	t.m.wg.Go(func() { t.probes(br, p, ts) })
	if rows {
		t.m.wg.Go(func() { t.sendRows(p, ts) })
	}
}

// endRows ends the rows that the member of the new session s gave on a session
// before. The member gives its rows again on s.
func (t *trunk) endRows(s *MeshSession) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	// The hook of a newer session of the member does this later.
	if mem := t.m.members[s.name]; mem == nil || mem.sess == nil || mem.sess == s {
		t.r.endIn(s.name, s)
	}
}

// changed removes the keys of a member that is down. The keys stay while the
// mesh has the member as up, so also for a short time after its session ended.
func (t *trunk) changed(c MeshChange) {
	if c.Up {
		return
	}
	// Mesh.mu keeps a new session out until the keys are removed.
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	var cur *MeshSession
	if mem := t.m.members[c.Name]; mem != nil {
		cur = mem.sess
	}
	// The rows of a member end with its attachments. A lost member keeps them.
	if c.Down == MeshRestart || c.Down == MeshRemoved {
		t.r.endIn(c.Name, cur)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.pairs[c.Name]
	if p == nil {
		return
	}
	if cur != nil && p.txFrom == cur {
		// The member has a new session and gave these SAs on it. The offer
		// of this relay on that session comes next.
		t.revokeRx(p)
		return
	}
	t.remove(p)
	slog.Info("Removed the trunk keys of a mesh member", "relay", c.Name, "reason", c.Down.String())
}

// give sends the receive SAs of this relay to the member of p on ts: a new
// offer first, then each rekey, until the session ends.
func (t *trunk) give(br *bridge, p *trunkPair, ts *trunkSession) {
	ctx := ts.s.Context()
	defer t.ended(p, ts)
	var wait redial
	for {
		select {
		case <-ctx.Done():
			return
		case <-ts.wake:
		}
		for {
			req, more, err := t.next(br, p, ts, time.Now())
			if err == nil && !more {
				break
			}
			if err == nil {
				err = t.send(ctx, br, p, ts, req)
			}
			if err == nil {
				wait = redial{}
				continue
			}
			if ctx.Err() != nil || errors.Is(err, errTrunkEnded) {
				return
			}
			if rpc.CodeOf(err) == rpc.Unimplemented {
				slog.Info("Mesh member has no trunk", "relay", p.name)
				t.mu.Lock()
				if p.sess == ts {
					t.revokeRx(p)
				}
				t.mu.Unlock()
				return
			}
			if wait.wait == 0 {
				slog.Warn("Failed to give trunk keys to a mesh member", "relay", p.name, "error", err)
			} else {
				slog.Debug("Failed to give trunk keys to a mesh member", "relay", p.name, "error", err)
			}
			// The member can have a part of the keys, so the next try is a new offer.
			t.mu.Lock()
			ts.fresh = true
			t.mu.Unlock()
			timer := time.NewTimer(wait.next())
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return
			}
		}
	}
}

// ended tells the pair that the key exchange on ts stopped.
func (t *trunk) ended(p *trunkPair, ts *trunkSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p.sess == ts {
		p.sess = nil
	}
}

// next returns the key change that the member of p gets next on ts: a new
// offer of all lanes, or the oldest rekey that waits. more is false for none.
func (t *trunk) next(br *bridge, p *trunkPair, ts *trunkSession, now time.Time) (req keys.Request, more bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p.gone || p.sess != ts {
		return keys.Request{}, false, errTrunkEnded
	}
	if ts.fresh {
		if p.rx == nil {
			// The largest payload sets the packet limit of the SAs. Only the
			// lane for PSP packets has no replay window.
			rx, err := br.recv.NewPeer(keys.PeerConfig{Trunk: true, MTU: trunkPayload, Lanes: trunkLanes, NoReplayLanes: trunkLanePSP + 1})
			if err != nil {
				return keys.Request{}, false, err
			}
			p.rx = rx
			t.byRx[rx] = p
		}
		if req, err = p.rx.Offer(now); err != nil {
			return keys.Request{}, false, err
		}
		t.addSPIs(p, req.SAs, ts.s)
		ts.fresh, p.pending = false, nil
		return req, true, nil
	}
	if len(p.pending) == 0 {
		return keys.Request{}, false, nil
	}
	req, p.pending = p.pending[0], p.pending[1:]
	return req, true, nil
}

// send gives req to the member of p in a TrunkKeys call. The member refuses an
// SPI that it holds from another receiver, and gets a new SA for that lane.
func (t *trunk) send(ctx context.Context, br *bridge, p *trunkPair, ts *trunkSession, req keys.Request) error {
	for range maxClashes + 1 {
		cctx, cancel := context.WithTimeout(ctx, trunkKeysTimeout)
		res, err := ts.s.Client().TrunkKeys(cctx, keyproto.ToProto(req))
		cancel()
		if err != nil {
			return err
		}
		var done bool
		if req, done, err = t.accepted(br, p, ts, res.GetRefusedSpis(), time.Now()); err != nil || done {
			return err
		}
	}
	return errTrunkRefused
}

// accepted keeps the answer of the member of p to a key change on ts. For
// refused SPIs it returns the offer of new SAs for their lanes, else done.
func (t *trunk) accepted(br *bridge, p *trunkPair, ts *trunkSession, refused []uint32, now time.Time) (next keys.Request, done bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p.gone || p.sess != ts || p.rx == nil {
		return keys.Request{}, false, errTrunkEnded
	}
	if len(refused) > 0 {
		if next, err = p.rx.Refused(refused, now); err != nil {
			return keys.Request{}, false, err
		}
		// The receiver deleted the refused SAs.
		t.prune(br, p)
		if len(next.SAs) > 0 {
			t.addSPIs(p, next.SAs, ts.s)
			return next, false, nil
		}
	}
	ts.offered = true
	t.ready(p)
	return keys.Request{}, true, nil
}

// ready starts the probes of the session of p when each relay of the pair
// gave its keys on that session. t.mu must be held.
func (t *trunk) ready(p *trunkPair) {
	ts := p.sess
	if ts == nil || !ts.offered || ts.probing || p.txFrom != ts.s || p.tx.SA(trunkLaneInner) == nil {
		return
	}
	ts.probing = true
	close(ts.ready)
}

// rekeyed takes the rekeys of the trunk peers out of ups and gives each one
// to the key exchange of its pair. It returns the other updates.
func (t *trunk) rekeyed(br *bridge, ups []keys.Update) []keys.Update {
	t.mu.Lock()
	defer t.mu.Unlock()
	rest := ups[:0]
	for _, u := range ups {
		p := t.byRx[u.Peer]
		if p == nil {
			rest = append(rest, u)
			continue
		}
		// Only the key exchange of the session now sends the rekey. A later
		// session gets a new offer, and not this rekey.
		var s *MeshSession
		if p.sess != nil {
			s = p.sess.s
		}
		t.addSPIs(p, u.SAs, s)
		p.pending = append(p.pending, u.Request)
		if p.sess != nil {
			select {
			case p.sess.wake <- struct{}{}:
			default:
			}
		}
	}
	// The receiver deleted the SAs that ended.
	for _, p := range t.pairs {
		t.prune(br, p)
	}
	return rest
}

// TrunkKeys applies the trunk SAs that the calling relay gives for packets to
// it. The caller is the member of the session, never a name in the request.
func (m *Mesh) TrunkKeys(ctx context.Context, in *dp.KeysRequest) (*dp.KeysResponse, error) {
	s, err := m.SessionOf(ctx)
	if err != nil {
		return nil, err
	}
	t := m.trunk.Load()
	if t == nil {
		return nil, rpc.Errorf(rpc.Unimplemented, "relay has no trunk")
	}
	req, err := keyproto.FromProto(in)
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	refused, err := t.apply(s, req, time.Now())
	if err != nil {
		return nil, err
	}
	return &dp.KeysResponse{RefusedSpis: refused}, nil
}

// apply applies the key change req of the member of s to the SAs for packets
// to that member. It returns the SPIs that this relay holds from another receiver.
func (t *trunk) apply(s *MeshSession, req keys.Request, now time.Time) ([]uint32, error) {
	br := t.r.bridge.Load()
	if br == nil {
		return nil, rpc.Errorf(rpc.Unavailable, "relay has no PSP bridge")
	}
	if got := s.Version().GetRevision(); got < trunkRevision {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "revision %d has no trunk", got)
	}
	for _, sa := range req.SAs {
		// A trunk SA has no VNI. The VNI field of its packets has the sender tag.
		if sa.VNI != 0 {
			return nil, rpc.Errorf(rpc.InvalidArgument, "SA %#x has VNI %#x, and a trunk SA has VNI 0", sa.SPI, sa.VNI)
		}
		if sa.Lane < 0 || sa.Lane >= trunkLanes {
			return nil, rpc.Errorf(rpc.InvalidArgument, "SA %#x has lane %d, and a trunk has lanes 0 and 1", sa.SPI, sa.Lane)
		}
	}
	// Mesh.mu keeps a newer session out, so that its keys do not come first.
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	if mem := t.m.members[s.name]; mem == nil || mem.sess != s {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "relay %q is not a member with this session", s.name)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.pairOf(br, s)
	refused, err := p.tx.Apply(req, now)
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	p.txFrom = s
	t.carry(p)
	t.ready(p)
	return refused, nil
}

// probes runs the full-size probe of p on ts when the pair has keys in both
// directions. After a failed run, it starts a run again each 30 s.
func (t *trunk) probes(br *bridge, p *trunkPair, ts *trunkSession) {
	ctx := ts.s.Context()
	select {
	case <-ctx.Done():
		return
	case <-ts.ready:
	}
	for {
		ok := t.probe(ctx, br, p)
		if ctx.Err() != nil {
			return
		}
		if !t.setPath(p, ts, ok) || ok {
			return
		}
		timer := time.NewTimer(trunkProbeRetry)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

// setPath keeps the result of a probe run of ts. It returns false if ts is
// not the session of p now.
func (t *trunk) setPath(p *trunkPair, ts *trunkSession, ok bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p.gone || p.sess != ts {
		return false
	}
	path := trunkPathLimited
	if ok {
		path = trunkPathFull
	}
	if old := trunkPath(p.path.Swap(uint32(path))); old == path {
		return true
	}
	if ok {
		slog.Info("Trunk path carries full-size packets", "relay", p.name, "mtu", trunkMTU)
	} else {
		slog.Warn("Trunk path does not carry full-size packets", "relay", p.name, "mtu", trunkLimitedMTU)
	}
	return true
}

// probe sends full-size trunk packets to the member of p and reports whether
// an answer of the same size came in time.
func (t *trunk) probe(ctx context.Context, br *bridge, p *trunkPair) bool {
	run := &trunkProbe{ok: make(chan struct{})}
	_, _ = rand.Read(run.id[:])
	p.run.Store(run)
	defer p.run.CompareAndSwap(run, nil)
	msg := make([]byte, trunkPayload)
	msg[0] = trunkMsgProbe
	copy(msg[1:], run.id[:])
	pkt := make([]byte, maxUDP)
	wait := time.NewTimer(trunkProbeWait)
	defer wait.Stop()
	tick := time.NewTicker(trunkProbeInterval)
	defer tick.Stop()
	for round := 0; ; {
		if round < trunkProbeRounds {
			if err := p.sendMessage(br, pkt, msg); err != nil {
				slog.Debug("Failed to send a trunk probe", "relay", p.name, "error", err)
			}
			round++
		}
		select {
		case <-run.ok:
			return true
		case <-wait.C:
			return false
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

// sendMessage seals msg, a message of the relay itself, into pkt and sends it
// to the member of p.
func (p *trunkPair) sendMessage(br *bridge, pkt, msg []byte) error {
	sa := p.tx.SA(trunkLaneInner)
	if sa == nil {
		return errNoSA
	}
	// The library does not read this payload, as with the PSP packet of an agent.
	n, err := sa.SealTrunkPSP(trunkTagRelay, pkt, msg)
	if err != nil {
		return err
	}
	_, err = br.tr.WriteTo(pkt[:n], p.udp)
	return err
}

// receive opens the trunk packet pkt from the address of the member of p, and sends
// the packet of a sender on. buf holds a sealed packet. It returns the drop reason.
func (t *trunk) receive(br *bridge, p *trunkPair, pkt, buf []byte, fwd forwarder, now time.Time) (dropReason, bool) {
	if br == nil || len(pkt) < pspwire.Overhead {
		return dropMalformed, false
	}
	// The SPI check comes first, so that a member cannot use the SA of another.
	sa, ok := p.sa(binary.BigEndian.Uint32(pkt[4:8]))
	if !ok {
		return dropMalformed, false
	}
	// The trunk SAs are in the receive queue of the bridge, which takes one
	// goroutine at a time.
	br.rxMu.Lock()
	payload, tag, next, err := br.rxq.ReceiveTrunk(pkt)
	br.rxMu.Unlock()
	switch {
	case errors.Is(err, engine.ErrPayload):
		// The SA for whole PSP packets had a payload of another type.
		return dropTrunkLane, false
	case errors.Is(err, engine.ErrReplay):
		return dropTrunkReplay, false
	case err != nil:
		return dropMalformed, false
	case tag == trunkTagRelay:
		return dropMalformed, p.message(br, payload)
	case sa.lane == trunkLanePSP:
		return t.r.pass(p.name, tag, payload, fwd, now)
	case next == pspwire.NextHdrPSP:
		// A relay sends the PSP packet of a sender only on the lane for PSP packets.
		return dropTrunkLane, false
	}
	return t.r.bridgeIn(p.name, sa.sess, tag, pkt, payload, buf, fwd)
}

// message handles a message of the member itself: a full-size probe, which
// gets an answer of the same size, or the answer to a probe of this relay.
func (p *trunkPair) message(br *bridge, msg []byte) bool {
	if len(msg) < trunkProbeLen {
		return false
	}
	switch msg[0] {
	case trunkMsgProbe:
		if !p.answers.Allow() {
			return false
		}
		msg[0] = trunkMsgReply
		return p.sendMessage(br, make([]byte, len(msg)+pspwire.Overhead), msg) == nil
	case trunkMsgReply:
		run := p.run.Load()
		if run == nil || len(msg) != trunkPayload || [trunkProbeLen - 1]byte(msg[1:trunkProbeLen]) != run.id {
			return false
		}
		run.once.Do(func() { close(run.ok) })
		return true
	}
	return false
}
