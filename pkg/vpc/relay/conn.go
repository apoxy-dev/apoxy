// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/emptypb"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// probeRate is the most path probes per second that one connection gets replies to.
const probeRate = 10

// Events of A from its tasks and children.
type (
	readerDone   struct{ err error }
	writerDone   struct{}
	trustChecked struct {
		t   *trustGen
		err error
	}
	prevExpired struct{ addr netip.AddrPort }
	checkLost   struct{ c *checkProc }
)

// keyJob is one key operation of A. The root runs them in order, one at a time.
type keyJob struct {
	op  keyOp // opApply for a Rekey call: A changes it to opOffer in QUIC mode.
	req keys.Request
	gen uint64 // Generation of the Rekey call, which goes in the offer.
	res chan callResult
}

// connAtt is one attachment of A, from the Attach call to its end.
type connAtt struct {
	att      *Attachment
	routes   []netip.Prefix // The advertised routes of the call.
	cell     uint32         // The transmit cell, from the root.
	instance uint64
	since    time.Time
	statuses []*dpv1.RouteStatus
	res      chan callResult // The Attach call, until it is answered.
	assigned bool
	// detach is the Detach call that waits for V, or nil.
	detach chan callResult
}

// connProc is the process A of one agent connection. It owns the ports, classify and source
// entries of its port, and the cells of the port and of its attachments.
type connProc struct {
	r      *Router
	t      dp.Target
	vbox   *mailbox
	box    *mailbox
	down   *valueMap
	up     *valueMap
	l      *link
	st     sessionStream
	hello  *dpv1.Hello
	port   uint64
	tag    uint32
	cell   uint32
	meter  uint32
	ctx    context.Context
	cancel context.CancelFunc

	net Network
	ref *dpv1.VPCRef
	s   session
	out *outbox

	trust    *trustGen // The newest trust value.
	checking bool

	mode    dpv1.Mode
	addr    netip.AddrPort // The source of the newest path probe.
	written netip.AddrPort // The PSP address of the ports entry in the data plane.
	prev    netip.AddrPort
	prevT   *time.Timer
	lanes   []uint16
	receive bool   // The agent reads the lane ports.
	seen    uint8  // Bit i is set after a keepalive from lane port i.
	told    vLanes // The lane ports that the root has.
	probes  uint64 // The largest counter of a valid path probe.
	limit   *rate.Limiter
	check   *checkProc
	// sources has the source entries of the port.
	sources map[netip.Prefix]struct{}

	atts    []*connAtt // Attached, the oldest first.
	pend    map[string]*connAtt
	rxBase  tally
	rxSum   uint64 // The receive count of the last RxReport.
	noRoute map[netip.Addr]time.Time
	live    liveness
	state   dpv1.AnnouncerState
	drained bool
	alts    []*dpv1.RelayRef

	// handovers counts the detaches of the oldest attachment that did not read the receive count
	// yet. Until then, rxBase stays the base of that attachment.
	handovers int

	jobs []keyJob
	cur  *keyJob // The job that the root runs now.

	// w sends the table changes of A up through V. portDirty and srcDirty ask for the ports entry
	// and the source entries of now in the next event, and next has the other updates.
	w         tableWriter
	portDirty bool
	srcDirty  bool
	next      batch
	// opened is true after the write of the first entries. A keeps the calls until then.
	opened bool
	calls  []aCall

	closing    bool
	keysClosed bool
	readerOn   bool
	writerOn   bool
	ends       []vAttachmentEnd
	// code and msg close the connection. lost has the slot losses that wait for the delete of the
	// ports entry, and portGone is true after it.
	code     dpv1.RelayCloseCode
	msg      string
	lost     []chan struct{}
	portGone bool
}

// startConn starts the A of e. V owns down and up.
func startConn(r *Router, vbox *mailbox, e toConn, down, up *valueMap, draining bool, alts []*dpv1.RelayRef) {
	ctx, cancel := context.WithCancel(context.Background())
	n := *load[*Network](down, keyNetwork)
	a := &connProc{
		r:       r,
		t:       r.cfg.Target,
		vbox:    vbox,
		box:     e.box,
		down:    down,
		up:      up,
		l:       e.l,
		st:      e.st,
		hello:   e.hello,
		port:    e.port,
		tag:     e.tag,
		cell:    e.cell,
		meter:   e.meter,
		ctx:     ctx,
		cancel:  cancel,
		net:     n,
		ref:     &dpv1.VPCRef{ProjectId: e.l.vpc.Project, VpcUid: e.l.vpc.UID, NetworkId: n.ID},
		s:       session{agent: agentKey{id: e.l.subject, name: e.hello.GetName(), instance: e.hello.GetInstance()}, meshRoutes: !e.hello.GetLocalRoutesOnly()},
		out:     newOutbox(),
		mode:    dpv1.Mode_MODE_QUIC,
		limit:   rate.NewLimiter(probeRate, probeRate),
		sources: map[netip.Prefix]struct{}{},
		pend:    map[string]*connAtt{},
		noRoute: map[netip.Addr]time.Time{},
		state:   stateNormal,
		drained: draining,
		alts:    alts,
		told:    vLanes{port: e.port},
	}
	// The first change has each key: A checks the cert with the trust data of now.
	watch(ctx, down, func(keys []string) { a.box.send(valuesChanged{keys: keys}) })
	go a.run()
}

func (a *connProc) run() {
	now := time.Now()
	a.live.last, a.live.since = now, now
	a.live.received = func() uint64 { return a.l.qc.ConnectionStats().PacketsReceived }
	a.live.count = a.live.received()
	a.start()
	a.runJobs()
	tick := time.NewTicker(livenessInterval)
	defer tick.Stop()
	for !a.finished() {
		select {
		case <-a.box.sig:
			for _, e := range a.box.take() {
				a.handle(e)
			}
		case now := <-tick.C:
			a.tick(now)
		}
		// The key jobs go up after the table changes of the same step.
		a.runJobs()
	}
	a.cancel()
	for _, e := range a.box.close() {
		a.refuse(e)
	}
	a.vbox.send(aEnded{port: a.port, ends: a.ends})
	a.l.streamEnd()
}

// finished reports whether A closed and each of its tasks and tables events ended.
func (a *connProc) finished() bool {
	return a.closing && a.keysClosed && !a.readerOn && !a.writerOn && !a.w.pending() && !a.tablesWait()
}

// start sends the entries of the port in QUIC mode up. A opens and sends Welcome after their write.
func (a *connProc) start() {
	var b batch
	md := portKey(a.port)
	pa := a.portAction()
	b.port(p4.Update_INSERT, a.port, &pa, md)
	b.insert(dp.ClassifyKey{Port: a.port, Session: accessSession}.Entry(dp.ContextAction{
		VPC: vpcName(a.l.vpc, a.net.ID), VNI: a.net.ID, Cell: a.cell,
	}), md)
	cfg := &a.r.cfg
	b.meter(dp.MeterPort, a.meter, cfg.TunnelRate, cfg.TunnelBurst)
	for lane := range uint32(dpLanes) {
		b.meter(dp.MeterLane, dpLanes*a.meter+lane, cfg.LaneRate, cfg.LaneBurst)
	}
	a.t.SetDatagramWriter(a.port, a.writeDatagram)
	a.next = b
	a.w.chainThen(a.started)
}

// started takes the result of the write of the first entries: A opens, or closes.
func (a *connProc) started(err error) {
	if err != nil {
		slog.Error("Failed to write the entries of an agent connection", "vpc", a.l.vpc.UID, "agent", a.l.subject, "error", err)
		a.t.SetDatagramWriter(a.port, nil)
		a.l.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "relay failed to add the connection")
		a.closing, a.keysClosed = true, true
		a.refuseCalls()
		a.portIsGone()
		return
	}
	a.opened = true
	if a.closing {
		a.closePort()
		return
	}
	a.open()
}

// open starts the tasks of the connection and sends Welcome, Config and the route table. Then A
// takes the calls that came before.
func (a *connProc) open() {
	cfg := &a.r.cfg
	a.setState(a.stateNow(), "connection started")
	go func() { _ = dp.ReadDatagrams(a.ctx, a.t, a.l.qc, a.port, accessSession) }()
	head := []*dpv1.SessionResponse{
		{Msg: &dpv1.SessionResponse_Welcome{Welcome: &dpv1.Welcome{
			ReflexiveAddress: a.l.remote().String(),
			MaxLanes:         uint32(cfg.LaneSources),
			Version:          a.r.ver,
			// The host stays empty: the agent sends to the host that it dialed.
			PspPort: uint32(dataPort(cfg.Target)),
			RelayId: cfg.Relay.GetId(),
		}}},
		{Msg: &dpv1.SessionResponse_Config{Config: &dpv1.Config{
			Vpc:              a.ref,
			Mtu:              a.net.MTU,
			DnsServers:       a.net.DNSServers,
			DnsSearchDomains: a.net.DNSSearchDomains,
		}}},
	}
	if a.drained {
		// The Drain goes after the first table.
		a.out.queue(a.drainMsg())
	}
	w := &writer{st: a.st, values: a.down, s: a.s, out: a.out}
	a.readerOn, a.writerOn = true, true
	go func() {
		_ = w.run(a.ctx, head)
		a.box.send(writerDone{})
	}()
	go func() { a.box.send(readerDone{err: a.read()}) }()
	calls := a.calls
	a.calls = nil
	for _, c := range calls {
		a.call(c)
	}
}

// refuseCalls answers the calls that came before A opened.
func (a *connProc) refuseCalls() {
	for _, c := range a.calls {
		c.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "relay connection closed")}
	}
	a.calls = nil
}

// writeDatagram is the datagram writer of the port: it sends on the session connection. It runs
// under the read lock of the data plane.
func (a *connProc) writeDatagram(b []byte) error {
	return a.l.qc.TrySendDatagram(b)
}

// read reads the agent messages of the Session call until it ends.
func (a *connProc) read() error {
	connected := false
	for {
		m, err := a.st.Recv()
		if err != nil {
			return err
		}
		switch m := m.GetMsg().(type) {
		case *dpv1.SessionRequest_Ack:
		case *dpv1.SessionRequest_Status:
			// Only the first time to connect counts.
			if d := m.Status.GetConnectTime(); d != nil && !connected {
				connected = true
				connectSeconds.WithLabelValues(modeLabel(a.hello.GetMode())).Observe(d.AsDuration().Seconds())
			}
		case nil:
			slog.Debug("Ignoring an unknown message on a Session call", "agent", a.l.subject)
		default:
			return rpc.Errorf(rpc.InvalidArgument, "unexpected message on Session")
		}
	}
}

func (a *connProc) handle(e any) {
	if a.closing {
		a.refuse(e)
		return
	}
	switch e := e.(type) {
	case aCall:
		if !a.opened {
			a.calls = append(a.calls, e)
			return
		}
		a.call(e)
	case toTablesDone:
		a.w.done(e.err)
	case toAssigned:
		a.assigned(e)
	case attached:
		a.attached(e)
	case detached:
		a.detached(e)
	case toKeysDone:
		a.keysDone(e)
	case toRekeyed:
		if a.mode == dpv1.Mode_MODE_PSP {
			a.out.queue(&dpv1.SessionResponse{Msg: &dpv1.SessionResponse_Rekey{Rekey: keyproto.ToProto(e.req)}})
		}
	case toPacketIn:
		a.packetIn(e.pin, time.Now())
	case toStats:
		a.vbox.send(aStatsAnswer{port: a.port, ask: e.ask, stats: a.stats()})
	case toSlotLost:
		a.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "attachment address lease ended")
		a.whenPortGone(e.done)
	case toDrain:
		a.drained, a.alts = true, e.alternates
		// Before Welcome, the Drain goes after it.
		if a.opened {
			a.setState(a.stateNow(), "relay drains")
			a.out.queue(a.drainMsg())
		}
	case toEndConn:
		a.close(e.code, e.msg)
	case toEnd:
		a.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "relay does not serve the VPC")
	case valuesChanged:
		a.changed(e.keys)
	case trustChecked:
		a.trustChecked(e)
	case readerDone:
		a.readerOn = false
		msg := "Session call ended"
		if e.err != nil && !errors.Is(e.err, io.EOF) {
			msg = e.err.Error()
		}
		a.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, msg)
	case writerDone:
		a.writerOn = false
		a.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, "Session call ended")
	case prevExpired:
		if a.prev == e.addr {
			a.prev = netip.AddrPort{}
			a.writePort()
		}
	case checkLost:
		a.pathLost(e.c)
	}
}

// refuse answers an event that comes when A closes or after its end.
func (a *connProc) refuse(e any) {
	switch e := e.(type) {
	case aCall:
		e.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "relay connection closed")}
	case toSlotLost:
		a.whenPortGone(e.done)
	case toStats:
		a.vbox.send(aStatsAnswer{port: a.port, ask: e.ask})
	case toKeysDone:
		a.keysDone(e)
	case toTablesDone:
		a.w.done(e.err)
	case readerDone:
		a.readerOn = false
	case writerDone:
		a.writerOn = false
	}
}

func (a *connProc) call(e aCall) {
	switch e.kind {
	case callAttach:
		a.attach(e.in.(*dpv1.AttachRequest), e.res)
	case callDetach:
		a.detach(e.in.(*dpv1.DetachRequest).GetAttachmentId(), e.res)
	case callRekey:
		a.rekey(e.in.(*dpv1.KeysRequest), e.res)
	case callLanes:
		in := e.in.(*dpv1.RegisterLanesRequest)
		if err := a.registerLanes(in.GetPorts(), in.GetReceive()); err != nil {
			e.res <- callResult{err: err}
			return
		}
		// The answer goes after the write of the ports entry.
		a.w.chainThen(func(error) { e.res <- callResult{out: &emptypb.Empty{}} })
	}
}

// attach starts an attachment: its addresses come from an Assign task of the root.
func (a *connProc) attach(in *dpv1.AttachRequest, res chan callResult) {
	key, err := KeyOf(in.GetVpc())
	if err == nil && key != a.l.vpc {
		err = rpc.Errorf(rpc.PermissionDenied, "VPC %s/%s is not the VPC of the agent cert", key.Project, key.UID)
	}
	var ca *connAtt
	if err == nil {
		ca, err = newAttachment(key, a.l.subject, in)
	}
	if err != nil {
		res <- callResult{err: err}
		return
	}
	ca.att.NetworkID, ca.att.Network = a.net.ID, a.net.Name
	ca.res = res
	a.pend[ca.att.ID] = ca
	a.vbox.send(vAssign{port: a.port, att: ca.att})
}

// newAttachment returns an attachment with no routes, and the advertised routes of the request in
// the masked form, which acceptRoutes checks.
func newAttachment(vpc VPCKey, subject string, in *dpv1.AttachRequest) (*connAtt, error) {
	if err := ValidateAttachment(in.GetName(), in.GetLabels()); err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	att := &Attachment{VPC: vpc, Name: in.GetName(), Labels: in.GetLabels(), Subject: subject, Rank: in.GetRank()}
	var routes []netip.Prefix
	for _, r := range in.GetRoutes() {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, rpc.Errorf(rpc.InvalidArgument, "route: %v", err)
		}
		routes = append(routes, p.Masked())
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	att.ID = hex.EncodeToString(id[:])
	return &connAtt{att: att, routes: routes}, nil
}

// assigned takes the addresses of an attachment, writes its source entries and gives it to V.
func (a *connProc) assigned(e toAssigned) {
	ca := a.pend[e.att]
	if ca == nil {
		return
	}
	if e.err != nil {
		delete(a.pend, e.att)
		ca.res <- callResult{err: e.err}
		return
	}
	ca.assigned, ca.cell, ca.instance = true, e.cell, e.instance
	ca.att.Addresses = e.addrs
	ca.statuses = acceptRoutes(ca.att, ca.routes)
	// The other relays of a mesh refuse an announcement with more prefixes.
	if n := len(ca.att.Addresses) + len(ca.att.Routes); a.r.mesh != nil && n > maxEntryPrefixes {
		a.fail(ca, rpc.Errorf(rpc.InvalidArgument, "attachment has %d addresses and routes, and a relay with a mesh takes at most %d", n, maxEntryPrefixes))
		return
	}
	for _, p := range ca.att.prefixes() {
		if !p.IsValid() {
			a.fail(ca, rpc.Errorf(rpc.InvalidArgument, "prefix not valid"))
			return
		}
	}
	a.srcDirty = true
	a.w.chainThen(func(err error) {
		if a.pend[ca.att.ID] != ca {
			// A closed and answered the call.
			return
		}
		if err != nil {
			a.fail(ca, rpc.Errorf(rpc.Unavailable, "failed to write source entries: %v", err))
			return
		}
		a.vbox.send(aAttach{port: a.port, att: ca.att, cell: ca.cell})
	})
}

// fail ends an attachment that did not attach. The root frees its addresses and its cell.
func (a *connProc) fail(ca *connAtt, err error) {
	delete(a.pend, ca.att.ID)
	a.srcDirty = true
	a.next.zeroCell(ca.cell)
	a.w.chainThen(func(error) {
		a.vbox.send(vAttachmentEnd{port: a.port, att: ca.att, cell: ca.cell})
		ca.res <- callResult{err: err}
	})
}

// attached answers the Attach call after V wrote the route entries.
func (a *connProc) attached(e attached) {
	ca := a.pend[e.id]
	if ca == nil {
		return
	}
	if e.err != nil {
		a.fail(ca, e.err)
		return
	}
	delete(a.pend, e.id)
	ca.since = time.Now()
	if len(a.atts) == 0 && a.handovers == 0 {
		// The first attachment does not get what the agent sent before it.
		a.rxBase = a.rx()
	}
	a.atts = append(a.atts, ca)
	a.vbox.send(vAttachmentStart{port: a.port, att: ca.att})
	ca.res <- callResult{out: &dpv1.AttachResponse{
		AttachmentId: ca.att.ID,
		Routes:       ca.statuses,
		Addresses:    prefixStrings(ca.att.Addresses),
	}}
	ca.res = nil
}

// routeResult returns the answer for the advertised route p of an attachment with the addresses
// addrs. An agent finds the VPC network in the same way.
func routeResult(p netip.Prefix, addrs []netip.Prefix) dpv1.RouteResult {
	inVPC := func(a netip.Prefix) bool { return p.Overlaps(tunnet.NetworkPrefixOf(a.Addr())) }
	switch {
	case p.Bits() == 0:
		return dpv1.RouteResult_ROUTE_RESULT_DEFAULT_ROUTE
	case p.Addr().Is4() || p.Addr().Is4In6():
		return dpv1.RouteResult_ROUTE_RESULT_IPV4
	case slices.ContainsFunc(addrs, inVPC):
		return dpv1.RouteResult_ROUTE_RESULT_OVERLAPS_VPC
	}
	return dpv1.RouteResult_ROUTE_RESULT_ACCEPTED
}

// acceptRoutes gives att the routes that the relay accepts, and returns the answer for each route
// in the order of routes. Call it after att has addresses.
func acceptRoutes(att *Attachment, routes []netip.Prefix) []*dpv1.RouteStatus {
	out := make([]*dpv1.RouteStatus, len(routes))
	for i, p := range routes {
		res := routeResult(p, att.Addresses)
		out[i] = &dpv1.RouteStatus{Prefix: p.String(), Result: res}
		if res == dpv1.RouteResult_ROUTE_RESULT_ACCEPTED {
			att.Routes = append(att.Routes, p)
			continue
		}
		slog.Info("Refused an advertised route", "vpc", att.VPC.UID, "attachment", att.ID, "prefix", p, "reason", res.String())
	}
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// detach removes an attachment: V removes its candidates first.
func (a *connProc) detach(id string, res chan callResult) {
	i := slices.IndexFunc(a.atts, func(ca *connAtt) bool { return ca.att.ID == id })
	if i < 0 || a.atts[i].detach != nil {
		res <- callResult{err: rpc.Errorf(rpc.NotFound, "no attachment %q on this session", id)}
		return
	}
	a.atts[i].detach = res
	a.vbox.send(aDetach{port: a.port, id: id})
}

// detached ends an attachment after V deleted its route entries: its source entries go, then A
// reads and resets its transmit cell, and its final counts go to the root.
func (a *connProc) detached(e detached) {
	i := slices.IndexFunc(a.atts, func(ca *connAtt) bool { return ca.att.ID == e.id })
	if i < 0 {
		return
	}
	ca, oldest := a.atts[i], i == 0
	a.atts = slices.Delete(a.atts, i, i+1)
	if oldest {
		a.handovers++
	}
	a.srcDirty = true
	a.w.chainThen(func(error) {
		rx := a.rx()
		st := a.statsOf(ca, oldest, rx)
		if oldest {
			// The next oldest attachment gets the receive counts from here on.
			a.rxBase = rx
			a.handovers--
		}
		a.next.zeroCell(ca.cell)
		a.w.chainThen(func(err error) {
			if err != nil {
				slog.Error("Failed to reset a counter cell", "vpc", a.l.vpc.UID, "error", err)
			}
			a.vbox.send(vAttachmentEnd{port: a.port, att: ca.att, cell: ca.cell, stats: &st})
			ca.detach <- callResult{out: &emptypb.Empty{}}
		})
	})
}

// sourceChanges adds to b the changes of the source entries to the prefixes of the attachments
// that V has or gets, and returns that set.
func (a *connProc) sourceChanges(b *batch) map[netip.Prefix]struct{} {
	want := map[netip.Prefix]struct{}{}
	for _, ca := range a.atts {
		for _, p := range ca.att.prefixes() {
			want[p] = struct{}{}
		}
	}
	for _, ca := range a.pend {
		if ca.assigned {
			for _, p := range ca.att.prefixes() {
				want[p] = struct{}{}
			}
		}
	}
	md := portKey(a.port)
	for p := range want {
		if _, ok := a.sources[p]; !ok {
			b.insert(dp.SourceKey{Port: a.port, Session: accessSession, Src: p}.Entry(dp.NoAction{}), md)
		}
	}
	for p := range a.sources {
		if _, ok := want[p]; !ok {
			b.remove(dp.SourceKey{Port: a.port, Session: accessSession, Src: p}.Entry(nil))
		}
	}
	return want
}

// flush sends the table changes of A up through V when no event of A is at the root.
func (a *connProc) flush() {
	// An event with no updates runs its functions at once, and they can add changes.
	for !a.w.busy && (a.tablesWait() || len(a.w.wait) > 0) {
		a.sendTables()
	}
}

// sendTables sends the table changes of A up in one tables event: the ports entry, then the
// source entries, then the other updates.
func (a *connProc) sendTables() {
	var b batch
	var pa *dp.PortAction
	// After close, the ports entry and the source entries go with the deletes of close.
	if a.portDirty && !a.closing {
		p := a.portAction()
		pa = &p
		b.port(p4.Update_MODIFY, a.port, pa, portKey(a.port))
	}
	var want map[netip.Prefix]struct{}
	if a.srcDirty && !a.closing {
		want = a.sourceChanges(&b)
	}
	a.portDirty, a.srcDirty = false, false
	b = append(b, a.next...)
	a.next = nil
	a.w.send(b, func(err error) {
		if pa != nil {
			if err != nil {
				slog.Error("Failed to write the port entries of an agent connection", "vpc", a.l.vpc.UID, "agent", a.l.subject, "error", err)
			} else {
				a.written = pa.Addr
				a.tellLanes(*pa)
			}
		}
		if want != nil {
			if err != nil {
				slog.Error("Failed to write source entries", "vpc", a.l.vpc.UID, "agent", a.l.subject, "error", err)
			} else {
				a.sources = want
			}
		}
	}, func(b batch, chain bool) { a.vbox.send(vTables{port: a.port, b: b, chain: chain}) })
}

// tablesWait reports whether table changes of A wait for the next event.
func (a *connProc) tablesWait() bool { return a.portDirty || a.srcDirty || len(a.next) > 0 }

// rekey queues a key change of the agent. In QUIC mode it is the change to PSP mode.
func (a *connProc) rekey(in *dpv1.KeysRequest, res chan callResult) {
	req, err := keyproto.FromProto(in)
	if err != nil {
		res <- callResult{err: rpc.Errorf(rpc.InvalidArgument, "%v", err)}
		return
	}
	for _, sa := range req.SAs {
		switch {
		case sa.VNI != a.net.ID:
			err = rpc.Errorf(rpc.InvalidArgument, "SA %#x has VNI %#x, not the VNI %#x of the VPC", sa.SPI, sa.VNI, a.net.ID)
		case sa.Lane >= dpLanes:
			err = rpc.Errorf(rpc.InvalidArgument, "SA %#x has lane %d, and the relay takes lanes 0 to %d", sa.SPI, sa.Lane, dpLanes-1)
		}
		if err != nil {
			res <- callResult{err: err}
			return
		}
	}
	a.jobs = append(a.jobs, keyJob{op: opApply, req: req, gen: in.GetGeneration(), res: res})
	a.runJobs()
}

// runJobs sends the next key job to the root when no job runs. The table changes of A go up
// first, so the root writes them before the keys entries.
func (a *connProc) runJobs() {
	a.flush()
	for a.cur == nil && len(a.jobs) > 0 && !a.tablesWait() {
		j := a.jobs[0]
		a.jobs = a.jobs[1:]
		if j.op == opApply && a.mode == dpv1.Mode_MODE_QUIC {
			switch {
			case a.closing:
				j.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "relay connection closed")}
				continue
			case !a.addr.IsValid():
				j.res <- callResult{err: rpc.Errorf(rpc.FailedPrecondition, "session has no PSP address: no path probe passed")}
				continue
			case !a.out.room():
				j.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "no room for the relay SAs in the session queue")}
				continue
			}
			j.op = opOffer
		}
		a.cur = &j
		a.vbox.send(vKeys{port: a.port, op: j.op, req: j.req, vni: a.net.ID, mtu: int(a.net.MTU), chain: j.res != nil})
	}
}

// keysDone takes the result of the running key job.
func (a *connProc) keysDone(e toKeysDone) {
	j := a.cur
	if j == nil || j.op != e.op {
		return
	}
	a.cur = nil
	switch j.op {
	case opOffer:
		if e.err == nil && e.ok && !a.closing {
			a.mode = dpv1.Mode_MODE_PSP
			a.writePort()
			// The check, the relay offer and the answer go after the write of the address.
			a.w.chainThen(func(error) {
				if !a.closing {
					a.startCheck()
					rk := keyproto.ToProto(e.offer)
					rk.Generation = j.gen
					a.out.queue(&dpv1.SessionResponse{Msg: &dpv1.SessionResponse_Rekey{Rekey: rk}})
					modeChanges.Inc()
				}
				a.answerKeys(j, e)
			})
			break
		}
		a.answerKeys(j, e)
	case opApply:
		a.answerKeys(j, e)
	case opClose:
		a.keysClosed = true
	}
	a.runJobs()
}

func (a *connProc) answerKeys(j *keyJob, e toKeysDone) {
	if e.err != nil {
		j.res <- callResult{err: e.err}
		return
	}
	j.res <- callResult{out: &dpv1.KeysResponse{RefusedSpis: e.refused}}
}

// registerLanes replaces the lane ports of the connection: all or none. With receive, a lane goes
// to its lane port after a keepalive from that port.
func (a *connProc) registerLanes(ports []uint32, receive bool) error {
	if len(ports) > a.r.cfg.LaneSources {
		return rpc.Errorf(rpc.InvalidArgument, "%d lane ports is above the limit of %d", len(ports), a.r.cfg.LaneSources)
	}
	if !a.addr.IsValid() {
		return rpc.Errorf(rpc.FailedPrecondition, "session has no source address")
	}
	lanes := make([]uint16, 0, len(ports))
	for _, p := range ports {
		ap := netip.AddrPortFrom(a.addr.Addr(), uint16(p))
		switch {
		case p == 0 || p > 0xffff:
			return rpc.Errorf(rpc.InvalidArgument, "port %d is not valid", p)
		case ap == a.addr || ap == a.prev || slices.Contains(lanes, uint16(p)):
			return rpc.Errorf(rpc.InvalidArgument, "port %d is the session port or a repeated port", p)
		}
		lanes = append(lanes, uint16(p))
	}
	a.lanes, a.receive, a.seen = lanes, receive && len(lanes) > 0, 0
	a.writePort()
	return nil
}

// portAction returns the ports entry action of the connection now: in PSP mode with the address,
// the previous address, the lane ports and the lanes that had a keepalive.
func (a *connProc) portAction() dp.PortAction {
	pa := dp.PortAction{Session: accessSession, Tag: a.tag, MTU: uint16(a.net.MTU), MeterIndex: a.meter}
	if a.mode == dpv1.Mode_MODE_PSP {
		pa.Addr, pa.Prev, pa.Seen = a.addr, a.prev, a.seen
		for i, port := range a.lanes {
			pa.Lanes |= uint64(port) << (48 - 16*(i+1))
		}
	}
	return pa
}

// writePort puts the ports entry of the connection in the next tables event.
func (a *connProc) writePort() { a.portDirty = true }

// tellLanes tells the root the lane ports of the ports entry pa after its write.
func (a *connProc) tellLanes(pa dp.PortAction) {
	m := vLanes{port: a.port, seen: pa.Seen}
	for i := range m.lanes {
		if port := uint16(pa.Lanes >> (48 - 16*(i+1))); port != 0 {
			m.lanes[i] = netip.AddrPortFrom(pa.Addr.Addr(), port)
		}
	}
	if m != a.told {
		a.told = m
		a.vbox.send(m)
	}
}

// packetIn takes a probe, a keepalive or a MISS of the connection.
func (a *connProc) packetIn(pin packetIn, now time.Time) {
	switch pin.md.kind {
	case dp.KindPunt:
		if isKeepalive(pin.payload) {
			a.keepalive(pin.md.from)
			return
		}
		a.probe(pin.payload, pin.md.from, now)
	case dp.KindMiss:
		dst, ok := innerDst(pin.payload)
		if !ok || now.Sub(a.noRoute[dst]) < noRouteInterval {
			return
		}
		a.noRoute[dst] = now
		a.out.queue(&dpv1.SessionResponse{Msg: &dpv1.SessionResponse_NoRoute{NoRoute: &dpv1.NoRoute{Vpc: a.ref, Address: dst.String()}}})
	}
}

// keepalive takes a keepalive from a lane port of the connection. When the agent reads the lane
// ports, the relay then sends that lane to the lane port.
func (a *connProc) keepalive(src netip.AddrPort) {
	i := slices.Index(a.lanes, src.Port())
	if !a.receive || i < 0 || src.Addr() != a.addr.Addr() || a.seen&(1<<i) != 0 {
		return
	}
	a.seen |= 1 << i
	a.writePort()
}

// isKeepalive reports whether b is a lane keepalive.
func isKeepalive(b []byte) bool { return len(b) == 1 && b[0] == p2p.TypeKeepalive }

// probe answers a path probe from the IP address of the QUIC connection. A newer probe from a new
// source moves the PSP address. A probe with a BFD packet goes to the check.
func (a *connProc) probe(b []byte, src netip.AddrPort, now time.Time) {
	if a.l.remote().Addr().Unmap() != src.Addr().Unmap() || !a.limit.AllowN(now, 1) {
		return
	}
	pr, err := p2p.OpenProbe(b, &a.l.probe.Dialer)
	if err != nil || pr.Reply {
		return
	}
	// The agent can call Rekey when it has the reply, so the address comes first.
	if pr.Counter > a.probes {
		a.probes = pr.Counter
		a.setAddr(src)
	}
	n := len(b)
	reply := func(error) {
		if pr.BFD != nil {
			// The relay end of the check sends its own packets: no reply.
			if a.check != nil {
				a.check.box.send(checkProbe{pr: pr})
			}
			return
		}
		pr.Reply, pr.Seen = true, src
		sendRaw(a.t, src, p2p.AppendProbe(nil, pr, n, &a.l.probe.Listener))
	}
	if a.mode == dpv1.Mode_MODE_PSP && a.written != a.addr {
		// In PSP mode, the reply goes after the write of the address.
		a.w.chainThen(reply)
		return
	}
	reply(nil)
}

// setAddr makes src the PSP address. The previous address stays valid for rebindOverlap, and the
// lane ports, which were at the old address, go.
func (a *connProc) setAddr(src netip.AddrPort) {
	if src == a.addr {
		return
	}
	if a.addr.IsValid() {
		a.prev = a.addr
		prev := a.prev
		if a.prevT != nil {
			a.prevT.Stop()
		}
		a.prevT = time.AfterFunc(rebindOverlap, func() { a.box.send(prevExpired{addr: prev}) })
	}
	a.addr, a.lanes, a.receive, a.seen = src, nil, false, 0
	if a.check != nil {
		a.check.box.send(checkAddr{addr: src})
	}
	if a.mode == dpv1.Mode_MODE_PSP {
		a.writePort()
	}
}

// sendRaw sends b from the data port to the outer address to.
func sendRaw(t dp.Target, to netip.AddrPort, b []byte) {
	_ = t.PacketOut(&p4.PacketOut{Payload: b, Metadata: dp.PacketOutMeta{Kind: dp.KindRaw, To: to}.Metadata()})
}

// innerDst returns the destination of an IPv4 or IPv6 packet.
func innerDst(pkt []byte) (netip.Addr, bool) {
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, false
}

// startCheck starts the PSP path check at the change to PSP mode.
func (a *connProc) startCheck() {
	a.stopCheck()
	a.check = startCheck(a.t, a.box, &a.l.probe, a.addr)
}

func (a *connProc) stopCheck() {
	if a.check != nil {
		a.check.box.send(toEnd{})
		a.check = nil
	}
}

// pathLost changes the connection to QUIC mode after its PSP path check c failed: the ports entry
// has no address, and the root deletes the keys. The agent changes from its own end of the check.
func (a *connProc) pathLost(c *checkProc) {
	if a.check != c {
		return
	}
	a.check = nil
	a.mode = dpv1.Mode_MODE_QUIC
	a.writePort()
	// The agent is in QUIC mode after the Down packet, so the root writes the ports entry at once.
	a.w.chainThen(func(error) {})
	a.jobs = append(a.jobs, keyJob{op: opRevoke})
	a.runJobs()
	slog.Info("PSP path to an agent stopped; changed its connection from PSP mode to QUIC mode", "vpc", a.l.vpc.UID, "agent", a.s.agent.name)
}

// changed loads the values of V that changed.
func (a *connProc) changed(keys []string) {
	for _, k := range keys {
		switch k {
		case keyRoutes:
			a.out.poke()
		case keyNetwork:
			// The VNI and the MTU stay as they were at Welcome for the life of the connection, as today.
			if n := load[*Network](a.down, keyNetwork); n != nil {
				id, mtu := a.net.ID, a.net.MTU
				a.net = *n
				a.net.ID, a.net.MTU = id, mtu
			}
		case keyTrust:
			a.checkTrust(load[*trustGen](a.down, keyTrust))
		case keyRx:
			a.reportRx()
		}
	}
}

// reportRx sends the agent the receive counts of the relay SAs when they changed. The agent gives
// them to its breaker.
func (a *connProc) reportRx() {
	v := load[*rxValue](a.down, keyRx)
	if v == nil || v.packets == a.rxSum {
		return
	}
	a.rxSum = v.packets
	a.out.setReport(&dpv1.RxReport{Sas: v.sas})
}

// checkTrust checks the agent cert again with the trust data t, in a task. One check runs at a
// time; a newer value waits for it.
func (a *connProc) checkTrust(t *trustGen) {
	a.trust = t
	if a.checking {
		return
	}
	a.checking = true
	trust, chain, at := a.r.cfg.Trust, a.l.chain, a.l.verified
	go func() {
		// The check uses the handshake time, because a connection does not end with its cert.
		_, err := checkCert(trust, chain, at)
		a.box.send(trustChecked{t: t, err: err})
	}()
}

func (a *connProc) trustChecked(e trustChecked) {
	a.checking = false
	if e.err != nil {
		slog.Info("Closing an agent connection after a trust change", "vpc", a.l.vpc.UID, "agent", a.l.subject, "error", e.err)
		a.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_CERT, "agent cert rejected")
		return
	}
	if a.trust != e.t {
		a.checkTrust(a.trust)
	}
}

// tick checks the liveness of the agent and forgets old NoRoute times.
func (a *connProc) tick(now time.Time) {
	if a.closing || !a.opened {
		return
	}
	a.live.observe(now)
	reason := "agent answers again"
	if a.live.silent {
		reason = "no packet from the agent"
	}
	a.setState(a.stateNow(), reason)
	for dst, t := range a.noRoute {
		if now.Sub(t) >= noRouteInterval {
			delete(a.noRoute, dst)
		}
	}
}

// stateNow returns the state of the candidates of the connection: suspect for a silent agent, then
// draining in a drain.
func (a *connProc) stateNow() dpv1.AnnouncerState {
	switch {
	case a.live.silent:
		return stateSuspect
	case a.drained:
		return stateDraining
	}
	return stateNormal
}

// setState stores a new state for V.
func (a *connProc) setState(state dpv1.AnnouncerState, reason string) {
	if state == a.state && load[*stateValue](a.up, keyState) != nil {
		return
	}
	a.state = state
	store(a.up, keyState, &stateValue{state: state, reason: reason})
}

func (a *connProc) drainMsg() *dpv1.SessionResponse {
	d := &dpv1.Drain{}
	// An agent with one connection for each relay must stay on this relay.
	if a.s.meshRoutes {
		d.Alternates = a.alts
	}
	return &dpv1.SessionResponse{Msg: &dpv1.SessionResponse_Drain{Drain: d}}
}

// rx returns the receive counts of the connection.
func (a *connProc) rx() tally {
	rx, _, err := readCell(bg, a.t, a.cell)
	if err != nil {
		slog.Error("Failed to read a counter cell", "vpc", a.l.vpc.UID, "error", err)
	}
	return rx
}

// stats returns the counters of each attachment.
func (a *connProc) stats() []AttachmentStats {
	if len(a.atts) == 0 {
		return nil
	}
	rx := a.rx()
	out := make([]AttachmentStats, len(a.atts))
	for i, ca := range a.atts {
		out[i] = a.statsOf(ca, i == 0, rx)
	}
	return out
}

// statsOf returns the counters of ca: the receive counts of the connection if it is the oldest
// attachment, and the transmit counts of its cell.
func (a *connProc) statsOf(ca *connAtt, oldest bool, rx tally) AttachmentStats {
	_, tx, err := readCell(bg, a.t, ca.cell)
	if err != nil {
		slog.Error("Failed to read a counter cell", "vpc", a.l.vpc.UID, "error", err)
	}
	st := AttachmentStats{
		ID:        ca.att.ID,
		Instance:  ca.instance,
		VPC:       ca.att.VPC,
		Network:   ca.att.Network,
		Name:      ca.att.Name,
		Build:     a.hello.GetVersion().GetBuild(),
		Since:     ca.since,
		TXPackets: tx.packets,
		TXBytes:   tx.bytes,
		RTT:       a.l.qc.ConnectionStats().SmoothedRTT,
	}
	if oldest {
		st.RXPackets = sub(rx.packets, a.rxBase.packets)
		st.RXBytes = sub(rx.bytes, a.rxBase.bytes)
	}
	return st
}

func sub(x, y uint64) uint64 {
	if x < y {
		return 0
	}
	return x - y
}

// close ends the connection: the ports entry goes first, then the final counts are read, then the
// other entries go and the root deletes the keys. A ends when the root answers. Before the first
// entries are in, the delete waits for their write.
func (a *connProc) close(code dpv1.RelayCloseCode, msg string) {
	if a.closing {
		return
	}
	a.closing = true
	a.code, a.msg = code, msg
	a.t.SetDatagramWriter(a.port, nil)
	a.refuseCalls()
	if a.opened {
		a.closePort()
	}
}

// closePort deletes the ports entry, so that the cells of A count no more packets.
func (a *connProc) closePort() {
	a.portDirty, a.srcDirty = false, false
	a.next.port(p4.Update_DELETE, a.port, nil, "")
	a.w.then(func(err error) {
		if err != nil {
			slog.Error("Failed to delete the port entries of an agent connection", "vpc", a.l.vpc.UID, "error", err)
		}
		a.closeRest()
	})
}

// portIsGone closes the slot losses that waited for the delete of the ports entry.
func (a *connProc) portIsGone() {
	a.portGone = true
	for _, done := range a.lost {
		close(done)
	}
	a.lost = nil
}

// whenPortGone closes done after the delete of the ports entry.
func (a *connProc) whenPortGone(done chan struct{}) {
	if a.portGone {
		close(done)
		return
	}
	a.lost = append(a.lost, done)
}

// closeRest reads the final counts after the delete of the ports entry, then deletes the other
// entries and closes the keys.
func (a *connProc) closeRest() {
	a.portIsGone()
	rx := a.rx()
	for i, ca := range a.atts {
		st := a.statsOf(ca, i == 0, rx)
		a.ends = append(a.ends, vAttachmentEnd{port: a.port, att: ca.att, cell: ca.cell, stats: &st})
		if ca.detach != nil {
			ca.detach <- callResult{out: &emptypb.Empty{}}
		}
	}
	var b batch
	b.remove(dp.ClassifyKey{Port: a.port, Session: accessSession}.Entry(nil))
	for p := range a.sources {
		b.remove(dp.SourceKey{Port: a.port, Session: accessSession, Src: p}.Entry(nil))
	}
	b.zeroCell(a.cell)
	b.zeroPortDrops(a.meter)
	for _, ca := range a.atts {
		b.zeroCell(ca.cell)
	}
	for _, ca := range a.pend {
		if ca.assigned {
			b.zeroCell(ca.cell)
		}
		ca.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "relay connection closed")}
	}
	a.next = append(a.next, b...)
	a.atts, a.pend, a.sources = nil, nil, nil
	code, msg := a.code, a.msg
	a.w.then(func(err error) {
		if err != nil {
			slog.Error("Failed to delete the entries of an agent connection", "vpc", a.l.vpc.UID, "error", err)
		}
		a.l.close(code, msg)
		a.cancel()
	})
	a.stopCheck()
	if a.prevT != nil {
		a.prevT.Stop()
	}
	for _, j := range a.jobs {
		if j.res != nil {
			j.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "relay connection closed")}
		}
	}
	a.jobs = []keyJob{{op: opClose}}
	a.runJobs()
}
