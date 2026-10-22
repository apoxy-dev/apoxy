// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// tickInterval is the time between two ticks of the key engine.
	tickInterval = time.Second
	// maxPacketIns is the most PacketIns that wait for the root. The data plane drops the others.
	maxPacketIns = 4096
	// maxCells and maxMeters are the sizes of the index pools: the cells counter has two indices
	// for each cell, and the port meter has one index for each port.
	maxCells  = 1 << 20
	maxMeters = 1 << 16
)

// bg is the context of the entry writes. A process writes and deletes its entries also while the
// relay stops.
var bg = context.Background()

// desiredState is what the host wants the relay to serve. It is immutable.
type desiredState struct {
	tenants map[string]struct{}
	vpcs    map[VPCKey]Network
}

// Router is the root process of the relay control plane. The host calls its methods from any
// goroutine; Run runs the process.
type Router struct {
	cfg  Config
	ver  *dpv1.Version
	box  *mailbox
	pins *mailbox
	// stateChanges counts the state changes of the connections with routes, by the new state.
	stateChanges [numAnnouncerStates]atomic.Uint64
	onEnd        atomic.Pointer[func(AttachmentStats)]

	desiredMu sync.Mutex
	desired   atomic.Pointer[desiredState]

	// The fields below belong to the goroutine of Run.
	keys     *keyEngine
	vs       map[VPCKey]*vChild
	conns    map[uint64]*rootConn
	sids     map[[8]byte]uint64
	lastPort uint64
	tag      uint32
	tags     map[uint32]struct{}
	cells    pool
	meters   pool
	attaches uint64
	hooks    []hookTask
	hookOn   bool
	asks     map[uint64]*statsRun
	lastAsk  uint64
	trust    map[string]*trustGen
	draining bool
	alts     []*dpv1.RelayRef
	stopping bool
	turns    turns
}

// vChild is the root side of one V.
type vChild struct {
	key    VPCKey
	net    Network
	box    *mailbox
	down   *valueMap
	ending bool
}

// rootConn is the root side of one access port.
type rootConn struct {
	port  uint64
	v     *vChild
	l     *link
	tag   uint32
	cell  uint32
	meter uint32
	atts  map[string]rootAtt // Assigned attachments that did not end.
	hooks int                // Hook tasks of the port that did not end.
	ended bool
	// rx is the sum of the receive counts that V has for the port, or -1 for none.
	rx int64
}

type rootAtt struct {
	att  *Attachment
	cell uint32
}

// hookTask is one call of a host hook. port is 0 for a task of no connection.
type hookTask struct {
	port uint64
	run  func()
}

// statsRun is one AttachmentStats ask that waits for the answers of the V processes.
type statsRun struct {
	reply chan []AttachmentStats
	wait  map[*vChild]struct{}
	out   []AttachmentStats
}

// NewRouter returns the root of a relay with cfg. Run starts it.
func NewRouter(cfg Config) (*Router, error) {
	if cfg.Relay.GetId() == "" {
		return nil, errors.New("relay config needs a relay ID")
	}
	if cfg.Target == nil {
		return nil, errors.New("relay config needs a data plane target")
	}
	if cfg.Addresses == nil {
		return nil, errors.New("relay config needs an address source")
	}
	if cfg.LaneRate > 0 && cfg.LaneBurst == 0 {
		cfg.LaneBurst = int(cfg.LaneRate / 10)
	}
	cfg.LaneBurst = max(cfg.LaneBurst, minBurst)
	if cfg.TunnelRate > 0 && cfg.TunnelBurst == 0 {
		cfg.TunnelBurst = int(cfg.TunnelRate / 10)
	}
	cfg.TunnelBurst = max(cfg.TunnelBurst, minBurst)
	cfg.LaneSources = min(max(cfg.LaneSources, 0), MaxLaneSources)
	k, err := newKeyEngine(cfg.Target)
	if err != nil {
		return nil, err
	}
	r := &Router{
		cfg:    cfg,
		ver:    dpv1.LocalVersion(build.BuildVersion),
		box:    newMailbox(0),
		pins:   newMailbox(maxPacketIns),
		keys:   k,
		vs:     map[VPCKey]*vChild{},
		conns:  map[uint64]*rootConn{},
		sids:   map[[8]byte]uint64{},
		tags:   map[uint32]struct{}{},
		cells:  pool{max: maxCells},
		meters: pool{max: maxMeters},
		asks:   map[uint64]*statsRun{},
		trust:  map[string]*trustGen{},
	}
	r.desired.Store(&desiredState{tenants: map[string]struct{}{}, vpcs: map[VPCKey]Network{}})
	return r, nil
}

// AddTenant tells the relay to serve the VPCs of project. It does not block.
func (r *Router) AddTenant(project string) {
	r.change(project, func(d *desiredState) { d.tenants[project] = struct{}{} })
}

// RemoveTenant ends the VPCs of project and their connections. It does not block.
func (r *Router) RemoveTenant(project string) {
	r.change(project, func(d *desiredState) {
		delete(d.tenants, project)
		maps.DeleteFunc(d.vpcs, func(k VPCKey, _ Network) bool { return k.Project == project })
	})
}

// AddVPC tells the relay to serve vpc with the data n. A later call with new data is a change; a
// new network ID ends the connections of the VPC. It does not block.
func (r *Router) AddVPC(vpc VPCKey, n Network) {
	r.change(vpc, func(d *desiredState) { d.vpcs[vpc] = n })
}

// RemoveVPC ends vpc and its connections. It does not block.
func (r *Router) RemoveVPC(vpc VPCKey) {
	r.change(vpc, func(d *desiredState) { delete(d.vpcs, vpc) })
}

// change makes a new desired state with fn and tells the root.
func (r *Router) change(key any, fn func(*desiredState)) {
	r.desiredMu.Lock()
	old := r.desired.Load()
	d := &desiredState{tenants: maps.Clone(old.tenants), vpcs: maps.Clone(old.vpcs)}
	fn(d)
	r.desired.Store(d)
	r.desiredMu.Unlock()
	r.box.send(desiredChanged{key: key})
}

// Recheck checks the agent certs of the open connections of project again, with the trust data of
// now. A connection whose cert fails closes with CERT.
func (r *Router) Recheck(project string) { r.box.send(recheckEv{project: project}) }

// OnAttachmentEnd sets the function that gets the final counters of each attachment that ends. It
// runs as a hook task. Set it before Run.
func (r *Router) OnAttachmentEnd(fn func(AttachmentStats)) { r.onEnd.Store(&fn) }

// AttachmentStats returns the counters of each live attachment, sorted by ID. It returns nil when
// the router does not run.
func (r *Router) AttachmentStats() []AttachmentStats {
	reply := make(chan []AttachmentStats, 1)
	if !r.box.send(statsAsk{reply: reply}) {
		return nil
	}
	return <-reply
}

// Run runs the root until ctx ends, then ends each V and waits for them and for the hook tasks.
func (r *Router) Run(ctx context.Context) error {
	r.cfg.Target.OnPacketIn(func(p *p4.PacketIn) bool {
		pin, ok := pinOf(p)
		return !ok || r.pins.send(pin)
	})
	defer r.cfg.Target.OnPacketIn(nil)
	tick := time.NewTicker(tickInterval)
	defer tick.Stop()
	done := ctx.Done()
	for {
		for _, e := range r.box.take() {
			r.turns.add(r.keyOf(e), e)
		}
		for _, e := range r.pins.take() {
			pin := e.(packetIn)
			r.turns.add(r.pinKey(pin), pin)
		}
		for {
			e, ok := r.turns.next()
			if !ok {
				break
			}
			r.handle(e)
		}
		if r.stopping && len(r.vs) == 0 && !r.hookOn && len(r.hooks) == 0 {
			r.pins.close()
			for _, e := range r.box.close() {
				r.refuse(e)
			}
			return nil
		}
		select {
		case <-r.box.sig:
		case <-r.pins.sig:
		case now := <-tick.C:
			if !r.stopping {
				r.tick(now)
			}
		case <-done:
			done = nil
			r.stop()
		}
	}
}

// keyOf returns the turn key of an event: its VPC, or nil for the host.
func (r *Router) keyOf(e any) any {
	switch e := e.(type) {
	case accepted:
		return e.l.vpc
	case desiredChanged:
		return e.key
	case fromV:
		return e.v.key
	case assignDone:
		return e.att.VPC
	case slotLost:
		if c := r.conns[e.port]; c != nil {
			return c.v.key
		}
	}
	return nil
}

func (r *Router) pinKey(pin packetIn) any {
	port := pin.md.port
	if port == 0 {
		if sid, ok := p2p.ProbeSID(pin.payload); ok {
			port = r.sids[sid]
		}
	}
	if c := r.conns[port]; c != nil {
		return c.v.key
	}
	return nil
}

// refuse answers an event that the root did not take, at its end.
func (r *Router) refuse(e any) {
	switch e := e.(type) {
	case accepted:
		e.res <- rpc.Errorf(rpc.Unavailable, "relay stopped")
	case slotLost:
		close(e.done)
	case statsAsk:
		e.reply <- nil
	}
}

func (r *Router) handle(e any) {
	switch e := e.(type) {
	case accepted:
		r.accept(e)
	case desiredChanged:
		r.reconcileKey(e.key)
	case recheckEv:
		r.recheck(e.project)
	case slotLost:
		r.slotLost(e)
	case drainEv:
		r.draining, r.alts = true, e.alternates
		for _, v := range r.vs {
			v.box.send(toDrain{alternates: e.alternates})
		}
	case endAllEv:
		for _, v := range r.vs {
			v.box.send(toEndConn{code: e.code, msg: e.msg})
		}
	case statsAsk:
		r.askStats(e)
	case packetIn:
		r.packetIn(e)
	case hookDone:
		r.hookOn = false
		r.nextHook()
	case hookPortDone:
		r.hookOn = false
		if c := r.conns[e.port]; c != nil {
			c.hooks--
			r.maybeForget(c)
		}
		r.nextHook()
	case assignDone:
		r.assigned(e)
	case fromV:
		r.fromV(e.v, e.msg)
	}
}

// hook queues a host hook call. The calls run one at a time, in order.
func (r *Router) hook(port uint64, fn func()) {
	if c := r.conns[port]; c != nil {
		c.hooks++
	}
	r.hooks = append(r.hooks, hookTask{port: port, run: fn})
	r.nextHook()
}

func (r *Router) nextHook() {
	if r.hookOn || len(r.hooks) == 0 {
		return
	}
	h := r.hooks[0]
	r.hooks = r.hooks[1:]
	r.hookOn = true
	go func() {
		h.run()
		if h.port != 0 {
			r.box.send(hookPortDone{port: h.port})
		} else {
			r.box.send(hookDone{})
		}
	}()
}

// network returns n with the MTU default and limit.
func network(n Network) Network {
	if n.MTU == 0 {
		n.MTU = vpcv1alpha1.DefaultMTU
	}
	// The API server checks the MTU only when the spec changes, so a network can have more.
	n.MTU = min(n.MTU, vpcv1alpha1.MaxMTU)
	return n
}

// reconcileKey reconciles a VPC, or each VPC of a tenant.
func (r *Router) reconcileKey(key any) {
	switch k := key.(type) {
	case VPCKey:
		r.reconcile(k)
	case string:
		keys := map[VPCKey]struct{}{}
		for vk := range r.vs {
			if vk.Project == k {
				keys[vk] = struct{}{}
			}
		}
		for vk := range r.desired.Load().vpcs {
			if vk.Project == k {
				keys[vk] = struct{}{}
			}
		}
		for vk := range keys {
			r.reconcile(vk)
		}
	}
}

// reconcile starts, changes or ends the V of key to match the desired state.
func (r *Router) reconcile(key VPCKey) {
	d := r.desired.Load()
	n, want := d.vpcs[key]
	if _, ok := d.tenants[key.Project]; !ok || r.stopping {
		want = false
	}
	n = network(n)
	v := r.vs[key]
	switch {
	case v == nil && want:
		r.startV(key, n)
	case v == nil, v.ending:
	case !want || n.ID != v.net.ID:
		// A new network ID is a new VPC in the data plane: V ends, and a new one starts at its end.
		v.ending = true
		v.box.send(toEnd{})
	case !equalNetwork(n, v.net):
		v.net = n
		store(v.down, keyNetwork, &n)
	}
}

func equalNetwork(a, b Network) bool {
	return a.ID == b.ID && a.Name == b.Name && a.MTU == b.MTU &&
		slices.Equal(a.DNSServers, b.DNSServers) && slices.Equal(a.DNSSearchDomains, b.DNSSearchDomains)
}

func (r *Router) startV(key VPCKey, n Network) {
	v := &vChild{key: key, net: n, box: newMailbox(0), down: &valueMap{}}
	store(v.down, keyNetwork, &n)
	store(v.down, keyTrust, r.trustOf(key.Project))
	r.vs[key] = v
	startVPC(r, v)
	if r.draining {
		v.box.send(toDrain{alternates: r.alts})
	}
}

// trustOf returns the trust value of a tenant.
func (r *Router) trustOf(project string) *trustGen {
	t := r.trust[project]
	if t == nil {
		t = &trustGen{}
		r.trust[project] = t
	}
	return t
}

func (r *Router) recheck(project string) {
	t := &trustGen{n: r.trustOf(project).n + 1}
	r.trust[project] = t
	for key, v := range r.vs {
		if key.Project == project {
			store(v.down, keyTrust, t)
		}
	}
}

// stop ends each V. Run returns when they ended.
func (r *Router) stop() {
	r.stopping = true
	for _, v := range r.vs {
		if !v.ending {
			v.ending = true
			v.box.send(toEnd{})
		}
	}
}

// accept gives a Session call with its Hello to the V of its VPC: a new A, or an extra connection
// of an A.
func (r *Router) accept(e accepted) {
	v := r.vs[e.l.vpc]
	if v == nil || v.ending || r.stopping {
		e.res <- rpc.Errorf(rpc.Unavailable, "relay does not serve VPC %s/%s", e.l.vpc.Project, e.l.vpc.UID)
		return
	}
	if x := e.hello.GetShard(); x != nil {
		e.l.extra.Store(true)
		if !v.box.send(toExtra{l: e.l, st: e.st, extra: x, res: e.res}) {
			e.res <- rpc.Errorf(rpc.Unavailable, "relay does not serve VPC %s/%s", e.l.vpc.Project, e.l.vpc.UID)
		}
		return
	}
	tag := r.newTag()
	if tag == 0 {
		e.res <- rpc.Errorf(rpc.ResourceExhausted, "relay has no free session tag")
		return
	}
	cell, ok := r.cells.get()
	if !ok {
		delete(r.tags, tag)
		e.res <- rpc.Errorf(rpc.ResourceExhausted, "relay has no free counter cell")
		return
	}
	meter, ok := r.meters.get()
	if !ok {
		delete(r.tags, tag)
		r.cells.put(cell)
		e.res <- rpc.Errorf(rpc.ResourceExhausted, "relay has no free meter")
		return
	}
	r.lastPort++
	c := &rootConn{port: r.lastPort, v: v, l: e.l, tag: tag, cell: cell, meter: meter, atts: map[string]rootAtt{}, rx: -1}
	r.conns[c.port] = c
	r.sids[e.l.probe.SID] = c.port
	e.l.owned.Store(true)
	// The calls of the agent wait in the mailbox of A until A starts.
	box := newMailbox(0)
	e.l.a.Store(box)
	if !v.box.send(toConn{l: e.l, st: e.st, hello: e.hello, box: box, port: c.port, tag: tag, cell: cell, meter: meter}) {
		c.ended = true
		e.l.streamEnd()
		r.maybeForget(c)
		e.res <- rpc.Errorf(rpc.Unavailable, "relay does not serve VPC %s/%s", e.l.vpc.Project, e.l.vpc.UID)
		return
	}
	e.res <- nil
}

// newTag returns a free 24-bit session tag, or 0 when none is free. A tag comes again only after
// all the other tags.
func (r *Router) newTag() uint32 {
	// A tag goes in the VNI field of a trunk packet, and 0 there is no tag.
	if len(r.tags) >= pspwire.MaxVNI {
		return 0
	}
	for {
		r.tag = r.tag%pspwire.MaxVNI + 1
		if _, used := r.tags[r.tag]; !used {
			r.tags[r.tag] = struct{}{}
			return r.tag
		}
	}
}

// maybeForget frees the indices of an ended port when its hook tasks ended, and tells the host.
func (r *Router) maybeForget(c *rootConn) {
	if !c.ended || c.hooks > 0 || r.conns[c.port] != c {
		return
	}
	delete(r.conns, c.port)
	if r.sids[c.l.probe.SID] == c.port {
		delete(r.sids, c.l.probe.SID)
	}
	delete(r.tags, c.tag)
	r.cells.put(c.cell)
	r.meters.put(c.meter)
	c.l.done()
}

func (r *Router) slotLost(e slotLost) {
	c := r.conns[e.port]
	if c == nil || c.ended || !c.v.box.send(toSlotLost{port: e.port, done: e.done}) {
		close(e.done)
	}
}

func (r *Router) packetIn(pin packetIn) {
	if pin.md.kind != dp.KindPunt && pin.md.kind != dp.KindMiss {
		return
	}
	port := pin.md.port
	if pin.md.kind == dp.KindPunt && port == 0 {
		// A probe: the port of its SID.
		sid, ok := p2p.ProbeSID(pin.payload)
		if !ok {
			return
		}
		port = r.sids[sid]
	}
	if c := r.conns[port]; c != nil && !c.ended {
		c.v.box.send(toPacketIn{port: port, pin: pin})
	}
}

func (r *Router) askStats(e statsAsk) {
	if len(r.vs) == 0 {
		e.reply <- nil
		return
	}
	r.lastAsk++
	run := &statsRun{reply: e.reply, wait: map[*vChild]struct{}{}}
	r.asks[r.lastAsk] = run
	for _, v := range r.vs {
		if v.box.send(toStats{ask: r.lastAsk}) {
			run.wait[v] = struct{}{}
		}
	}
	r.answerStats(r.lastAsk)
}

// answerStats answers an ask when no V is left to answer it.
func (r *Router) answerStats(ask uint64) {
	run := r.asks[ask]
	if run == nil || len(run.wait) > 0 {
		return
	}
	delete(r.asks, ask)
	slices.SortFunc(run.out, func(a, b AttachmentStats) int { return cmp.Compare(a.ID, b.ID) })
	run.reply <- run.out
}

// tick runs the rekeys and the expiry of the key engine, and gives each V the receive counts of
// its connections.
func (r *Router) tick(now time.Time) {
	rekeyed, rx := r.keys.tick(bg, now)
	for port, req := range rekeyed {
		if c := r.conns[port]; c != nil && !c.ended {
			c.v.box.send(toRekeyed{port: port, req: req})
		}
	}
	for port, v := range rx {
		if c := r.conns[port]; c != nil && !c.ended && int64(v.packets) != c.rx {
			c.rx = int64(v.packets)
			store(c.v.down, rxKey(port), v)
		}
	}
}

func (r *Router) assigned(e assignDone) {
	c := r.conns[e.port]
	if e.err == nil && (c == nil || c.ended) {
		// The connection ended before the result came.
		r.hook(0, func() { r.cfg.Addresses.Release(e.att) })
		return
	}
	if c == nil {
		return
	}
	res := toAssigned{port: e.port, att: e.att.ID, err: e.err}
	if e.err == nil {
		cell, ok := r.cells.get()
		if !ok {
			r.hook(e.port, func() { r.cfg.Addresses.Release(e.att) })
			res.err = rpc.Errorf(rpc.ResourceExhausted, "relay has no free counter cell")
		} else {
			r.attaches++
			e.att.Addresses = e.addrs
			c.atts[e.att.ID] = rootAtt{att: e.att, cell: cell}
			res.addrs, res.cell, res.instance = e.addrs, cell, r.attaches
		}
	}
	c.v.box.send(res)
}

func (r *Router) fromV(v *vChild, msg any) {
	switch m := msg.(type) {
	case vAssign:
		r.assign(m)
	case vKeys:
		r.runKeys(v, m)
	case vAttachmentStart:
		r.hook(m.port, func() { r.cfg.Addresses.Attached(m.att) })
	case vAttachmentEnd:
		r.attachmentEnd(m)
	case vConnEnded:
		r.connEnded(m)
	case vStatsAnswer:
		if run := r.asks[m.ask]; run != nil {
			delete(run.wait, v)
			run.out = append(run.out, m.stats...)
			r.answerStats(m.ask)
		}
	case vEnded:
		if r.vs[v.key] == v {
			delete(r.vs, v.key)
		}
		for ask, run := range r.asks {
			if _, ok := run.wait[v]; ok {
				delete(run.wait, v)
				r.answerStats(ask)
			}
		}
		r.reconcile(v.key)
	}
}

// assign runs the Assign hook of a new attachment. onLost waits until the connection of the
// attachment deleted its ports entry.
func (r *Router) assign(m vAssign) {
	c := r.conns[m.port]
	if c == nil || c.ended {
		return
	}
	port, att := m.port, m.att
	// The call ends when the connection closes, so a held Assign does not hold the hook tasks.
	ctx := c.l.qc.Context()
	r.hook(port, func() {
		addrs, err := r.cfg.Addresses.Assign(ctx, att, func() {
			done := make(chan struct{})
			if r.box.send(slotLost{port: port, att: att.ID, done: done}) {
				<-done
			}
		})
		if err != nil && rpc.CodeOf(err) == rpc.Unknown {
			err = rpc.Errorf(rpc.Unavailable, "no addresses: %v", err)
		}
		r.box.send(assignDone{port: port, att: att, addrs: addrs, err: err})
	})
}

// runKeys runs a key operation of an A, writes its keys entries and answers it.
func (r *Router) runKeys(v *vChild, m vKeys) {
	done := toKeysDone{port: m.port, op: m.op}
	now := time.Now()
	switch m.op {
	case opOffer:
		done.offer, done.refused, done.ok, done.err = r.keys.offer(bg, m.port, m.vni, m.mtu, m.req, now)
	case opApply:
		done.refused, done.err = r.keys.apply(bg, m.port, m.req, now)
	case opRevoke, opClose:
		if err := r.keys.close(bg, m.port); err != nil {
			slog.Warn("Failed to delete the keys entries of a connection", "port", m.port, "error", err)
		}
		if c := r.conns[m.port]; c != nil && c.rx >= 0 {
			c.rx = -1
			v.down.Delete(rxKey(m.port))
		}
	}
	v.box.send(done)
}

func (r *Router) attachmentEnd(m vAttachmentEnd) {
	c := r.conns[m.port]
	if c == nil {
		return
	}
	delete(c.atts, m.att.ID)
	r.cells.put(m.cell)
	r.endHooks(m)
}

// endHooks queues the hook tasks of the end of an attachment: its final counts, then Release.
func (r *Router) endHooks(m vAttachmentEnd) {
	if st := m.stats; st != nil {
		if fn := r.onEnd.Load(); fn != nil {
			r.hook(m.port, func() { (*fn)(*st) })
		}
	}
	r.hook(m.port, func() { r.cfg.Addresses.Release(m.att) })
}

// connEnded frees the attachments of an ended port, and then its indices.
func (r *Router) connEnded(m vConnEnded) {
	c := r.conns[m.port]
	if c == nil {
		return
	}
	c.ended = true
	for _, end := range m.ends {
		r.attachmentEnd(end)
	}
	// The assigned attachments that A did not take go back too.
	for id, a := range c.atts {
		delete(c.atts, id)
		r.cells.put(a.cell)
		r.endHooks(vAttachmentEnd{port: m.port, att: a.att})
	}
	if c.rx >= 0 {
		c.rx = -1
		c.v.down.Delete(rxKey(m.port))
	}
	r.maybeForget(c)
}

// turns has the events of the root in one queue for each key. A pass takes at most one event of
// each key, so a burst of one VPC does not delay another.
type turns struct {
	q     map[any][]any
	order []any
}

func (t *turns) add(key, e any) {
	if t.q == nil {
		t.q = map[any][]any{}
	}
	if len(t.q[key]) == 0 {
		t.order = append(t.order, key)
	}
	t.q[key] = append(t.q[key], e)
}

// next returns the next event: the first event of the next key in turn.
func (t *turns) next() (any, bool) {
	if len(t.order) == 0 {
		return nil, false
	}
	key := t.order[0]
	t.order = t.order[1:]
	q := t.q[key]
	e := q[0]
	if len(q) == 1 {
		delete(t.q, key)
	} else {
		t.q[key] = q[1:]
		t.order = append(t.order, key)
	}
	return e, true
}
