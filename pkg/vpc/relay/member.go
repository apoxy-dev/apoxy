// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// trunkLane is the one SA lane of a trunk.
	trunkLane  = 0
	trunkLanes = 1
	// trunkMTU is the largest inner packet between two relays.
	trunkMTU = maxUDP - pspwire.Overhead
	// trunkLimitedMTU is the inner MTU of a trunk with no full-size probe that passed. It is the
	// least MTU of a network.
	trunkLimitedMTU = vpcv1alpha1.DefaultMTU
	// The first byte of a message of the relay itself, with tag 0, is its type.
	trunkMsgProbe = 0x01
	trunkMsgReply = 0x02
	// trunkProbeLen is the type byte and the ID of the probe run.
	trunkProbeLen = 1 + 8
	// A probe run has the numbers of the path probe of an agent: up to 3 packets 300 ms apart,
	// and no answer in 1 s fails it.
	trunkProbeRounds   = 3
	trunkProbeInterval = 300 * time.Millisecond
	trunkProbeWait     = time.Second
	// trunkProbeRetry is the time from a failed run to the next run.
	trunkProbeRetry = 30 * time.Second
	// trunkKeysTimeout limits one TrunkKeys call.
	trunkKeysTimeout = 5 * time.Second
	// maxClashes limits the new offers when the member holds the SPIs from another receiver.
	maxClashes = 4

	// keyValues is the key of the member values in the up map of M.
	keyValues = "values"
	// keyPart is the prefix of the key of the part of a VPC in the up map of M.
	keyPart = "part/"
	// keyMember is the prefix of the key of a member in the down map of V.
	keyMember = "member/"
)

// memberValues is the trunk data of a member that V reads: where its candidates go. It is
// immutable.
type memberValues struct {
	inc  uint64
	ver  uint64
	ref  *dpv1.RelayRef
	port uint64
	cell uint32
	mtu  int
}

// memberView is what V gets of one member: its values and its part of the VPC. It is immutable.
type memberView struct {
	inc    uint64
	values *memberValues
	part   *recordSet
}

// trunkPath is the result of the full-size probe of a trunk.
type trunkPath uint8

const (
	pathUnknown trunkPath = iota
	pathFull
	pathLimited
)

// mSub is the state of M in up.
type mSub uint8

const (
	subKeying mSub = iota
	subProbing
	subFull
	subLimited
)

// kState is the state of the TrunkKeys calls of M.
type kState uint8

const (
	kIdle    kState = iota
	kOffer          // A key job for an offer runs in the root.
	kCalling        // A TrunkKeys call runs.
	kWaiting        // A failed call waits for the next try.
)

// Events of M from its tasks.
type (
	dialed struct {
		qc  *quic.Conn
		err error
	}
	redialEv   struct{}
	keysCalled struct {
		ms      *msProc
		refused []uint32
		err     error
	}
	keysRetry  struct{ ms *msProc }
	probeTick  struct{ run *probeRun }
	probeWait  struct{ run *probeRun }
	probeAgain struct{ run *probeRun }
	fetchDone  struct {
		n    uint64
		data []byte
		err  error
	}
)

// Messages of M to the root.
type (
	mKeys struct {
		op      keyOp
		session uint64
		req     keys.Request
		spis    []uint32
	}
	mChange  struct{ c MeshChange }
	mSession struct{ s *MeshSession }
	mFetched struct {
		n    uint64
		data []byte
		err  error
	}
	// mEnded is the end of M, with the final counts of its trunk port.
	mEnded struct{ final trunkCounts }
)

// Messages of the root to M.
type (
	toMConn struct {
		c    *meshConn
		open msOpen
		res  chan error
	}
	toTxExpired struct{}
	toAsk       struct{ reply chan askAnswer }
	toFetch     struct{ n uint64 }
	toMEnd      struct {
		code dpv1.MeshCloseCode
		msg  string
		down MeshDown
	}
)

type askAnswer struct {
	up bool
	s  *MeshSession
}

type fetchResult struct {
	data []byte
	from string
	err  error
}

// mJob is one key operation of M. The root runs them in order, one at a time.
type mJob struct {
	op   keyOp
	ms   *msProc
	req  keys.Request
	spis []uint32
	res  chan callResult
}

// probeRun is one probe run of the trunk.
type probeRun struct {
	ms    *msProc
	id    [trunkProbeLen - 1]byte
	round int
	tick  *time.Timer
	wait  *time.Timer
}

// tagState is the classify entry and the source entries of one sender tag of the member.
type tagState struct {
	name string // The VPC name in the data plane.
	vni  uint32
	recs map[*record]struct{}
	refs map[netip.Prefix]int
	// The entries in the data plane.
	classify bool
	sources  map[netip.Prefix]struct{}
}

// mChild is the root side of one M.
type mChild struct {
	name   string
	addr   netip.AddrPort
	inc    uint64
	port   uint64
	cell   uint32
	meter  uint32
	box    *mailbox
	down   *valueMap
	up     *valueMap
	cancel context.CancelFunc
	ending bool
	// isUp is true between the up change and the down change of the member.
	isUp bool
	s    *MeshSession
	// id is the last relay ID that the member gave, for the metrics while it has no session.
	id string
	// base is the final counts of the earlier M of the member, as its series go on.
	base trunkCounts
	// values and parts are the newest values of the up map that the root gave to V.
	values *memberValues
	parts  map[VPCKey]*recordSet
}

// mProc is the process M of one listed peer relay. It owns the ports entry of its trunk port,
// the classify and source entries of the records, and its cell.
type mProc struct {
	r      *Router
	c      *mChild
	box    *mailbox
	ctx    context.Context
	cancel context.CancelFunc
	dialer bool

	ms      *msProc // The MS that is up, or nil.
	opening *msProc // The MS of a dial, before Open.
	seq     uint64  // The number of the last MS.
	dialing bool
	wait    redial
	redialT *time.Timer
	everUp  bool
	isUp    bool
	session *MeshSession
	downWhy MeshDown
	closing bool // The keys of an ended MS close.

	sub     mSub
	path    trunkPath
	pathTo  netip.AddrPort
	ported  bool
	metered bool
	offered bool
	txOK    bool
	kst     kState
	fresh   bool
	tries   int
	kwait   redial
	kT      *time.Timer
	pending []keys.Request
	jobs    []mJob
	cur     *mJob
	run     *probeRun
	retryT  *time.Timer
	answers *rate.Limiter
	ver     uint64
	fetches int

	senders   map[string]*pProc
	receivers map[string]*pProc
	// failed has the tenants whose call ended for a cause other than a stall. They get no new
	// call until the next MS.
	failed map[string]bool
	ps     map[*pProc]context.CancelFunc // Each P that did not end, with the end of its watch.

	parts map[VPCKey]*recordSet
	tags  map[uint32]*tagState
	// tagSession is the session of the classify and source entries in the data plane.
	tagSession uint64

	ending     bool
	endDown    MeshDown
	keysClosed bool
}

// startMember starts the M of c.
func startMember(r *Router, c *mChild) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &mProc{
		r: r, c: c, box: c.box, ctx: ctx, cancel: cancel, dialer: r.mesh.name < c.name,
		answers: rate.NewLimiter(probeRate, probeRate), senders: map[string]*pProc{}, receivers: map[string]*pProc{},
		failed: map[string]bool{}, ps: map[*pProc]context.CancelFunc{}, parts: map[VPCKey]*recordSet{}, tags: map[uint32]*tagState{},
	}
	watch(ctx, c.down, func(keys []string) { m.box.send(valuesChanged{keys: keys}) })
	go m.loop()
}

func (m *mProc) loop() {
	m.startDial()
	for !m.done() {
		<-m.box.sig
		for _, e := range m.box.take() {
			m.handle(e)
		}
	}
	m.cancel()
	for _, e := range m.box.close() {
		m.refuse(e)
	}
	// The ports entry is gone: read the final counts, then reset the indices for the pools.
	final, err := readTrunk(bg, m.r.cfg.Target, m.c.cell, m.c.meter)
	if err != nil {
		slog.Error("Failed to read the final counts of a trunk", "relay", m.c.name, "error", err)
	}
	var b batch
	b.zeroCell(m.c.cell)
	b.zeroPortDrops(m.c.meter)
	if err := b.write(bg, m.r.cfg.Target); err != nil {
		slog.Error("Failed to reset the counts of a trunk", "relay", m.c.name, "error", err)
	}
	if m.everUp && m.endDown != 0 {
		m.toRoot(mChange{c: MeshChange{Name: m.c.name, Down: m.endDown}})
	}
	m.toRoot(mEnded{final: final})
}

// done reports whether M ended and each of its children and tasks ended.
func (m *mProc) done() bool {
	return m.ending && m.keysClosed && m.cur == nil && len(m.jobs) == 0 && m.ms == nil && m.opening == nil &&
		len(m.ps) == 0 && !m.dialing && m.kst != kCalling && m.fetches == 0
}

// toRoot sends msg to the root.
func (m *mProc) toRoot(msg any) { m.r.box.send(fromM{m: m.c, msg: msg}) }

func (m *mProc) handle(e any) {
	switch e := e.(type) {
	case dialed:
		m.dialed(e)
	case redialEv:
		m.redialT = nil
		m.startDial()
	case toMConn:
		m.accepted(e)
	case msUp:
		m.msUp(e.ms)
	case msEnded:
		m.msEnded(e)
	case mIncoming:
		m.incoming(e)
	case mTrunkApply:
		if e.ms != m.ms || m.ending {
			e.res <- callResult{err: rpc.Errorf(rpc.FailedPrecondition, "mesh session is not the session of the member now")}
			return
		}
		m.job(mJob{op: opApply, ms: e.ms, req: e.req, res: e.res})
	case toKeysDone:
		m.keysDone(e)
	case keysCalled:
		m.keysCalled(e)
	case keysRetry:
		if e.ms == m.ms && m.kst == kWaiting {
			m.kT, m.kst = nil, kIdle
			m.stepKeys()
		}
	case toRekeyed:
		if m.ms != nil && !m.ending {
			m.pending = append(m.pending, e.req)
			m.stepKeys()
		}
	case toTxExpired:
		m.txOK = false
		if m.ms != nil && m.sub != subKeying {
			slog.Info("Trunk has no transmit SA, keys again", "relay", m.c.name)
			m.stopProbe()
			m.sub = subKeying
			m.up().Delete(keyValues)
		}
	case toPacketIn:
		m.packetIn(e.pin)
	case probeTick:
		m.probeTick(e.run)
	case probeWait:
		if e.run == m.run && m.sub == subProbing {
			m.probed(false)
		}
	case probeAgain:
		if e.run == m.run && m.sub == subLimited && m.ms == e.run.ms {
			m.retryT = nil
			m.sub = subProbing
			m.startProbe()
		}
	case valuesChanged:
		m.setsChanged(e.keys)
	case pChanged:
		if m.receivers[e.p.tenant] == e.p {
			for _, k := range e.keys {
				if rs := load[*recordSet](e.p.up, k); rs != nil {
					m.records(rs.vpc, rs)
				}
			}
		}
	case pEnded:
		m.pEnded(e)
	case toAsk:
		e.reply <- askAnswer{up: m.ms != nil && !m.ending, s: m.session}
	case toFetch:
		m.fetch(e.n)
	case fetchDone:
		m.fetches--
		m.toRoot(mFetched{n: e.n, data: e.data, err: e.err})
	case toMEnd:
		m.end(e)
	}
}

// refuse answers an event that came after the end of M.
func (m *mProc) refuse(e any) {
	switch e := e.(type) {
	case toMConn:
		e.res <- errNotMember
	case mIncoming:
		e.done <- rpc.Errorf(rpc.Unavailable, "mesh session ended")
	case mTrunkApply:
		e.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "mesh session ended")}
	case toAsk:
		e.reply <- askAnswer{}
	case toFetch:
		m.toRoot(mFetched{n: e.n, err: rpc.Errorf(rpc.NotFound, "member ended")})
	}
}

// up returns the up map of M.
func (m *mProc) up() *valueMap { return m.c.up }

// Dials and sessions.

// startDial dials the member when this relay dials it and has no session.
func (m *mProc) startDial() {
	if !m.dialer || m.ending || m.dialing || m.opening != nil || m.ms != nil || m.redialT != nil {
		return
	}
	m.dialing = true
	cfg, addr := m.r.mesh, m.c.addr
	go func() {
		ctx, cancel := context.WithTimeout(m.ctx, meshOpenTimeout)
		defer cancel()
		qc, err := cfg.tr.Dial(ctx, net.UDPAddrFromAddrPort(addr), cfg.tls, cfg.quic)
		m.box.send(dialed{qc: qc, err: err})
	}()
}

func (m *mProc) dialed(e dialed) {
	m.dialing = false
	if e.err == nil && m.ending {
		_ = e.qc.CloseWithError(quic.ApplicationErrorCode(dpv1.MeshCloseCode_MESH_CLOSE_CODE_RESTART), "relay stops")
		return
	}
	if e.err != nil {
		m.dialFailed(fmt.Errorf("dial: %w", e.err))
		return
	}
	m.seq++
	m.opening = startMS(m.r, m.box, newMeshConn(e.qc, m.r.mesh.mux, true), m.c.name, m.seq, msOpen{})
}

// dialFailed waits before the next dial. The first failure after a session is a warning.
func (m *mProc) dialFailed(err error) {
	if m.ending {
		return
	}
	if err == nil {
		err = errors.New("session ended before Open")
	}
	if m.wait.wait == 0 {
		slog.Warn("Failed to open mesh session", "relay", m.c.name, "addr", m.c.addr, "error", err)
	} else {
		slog.Debug("Failed to open mesh session", "relay", m.c.name, "addr", m.c.addr, "error", err)
	}
	m.redialT = time.AfterFunc(m.wait.next(), func() { m.box.send(redialEv{}) })
}

// accepted takes a session that the member dialed and that passed Open.
func (m *mProc) accepted(e toMConn) {
	if m.ending {
		e.res <- errNotMember
		return
	}
	m.seq++
	startMS(m.r, m.box, e.c, m.c.name, m.seq, e.open)
	e.res <- nil
}

// msUp makes ms the session of the member. It replaces the session before, as Mesh.admit did.
func (m *mProc) msUp(ms *msProc) {
	if m.ending || (ms.c.dialer && ms != m.opening) || (m.ms != nil && ms.n < m.ms.n) {
		ms.box.send(msEnd{code: dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, msg: "mesh session is not the session of the member"})
		return
	}
	if m.opening == ms {
		m.opening = nil
	}
	if old := m.ms; old != nil {
		old.box.send(msEnd{code: dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, msg: "a new session replaced this one"})
		m.drop()
		m.job(mJob{op: opClose, ms: old})
	}
	m.ms = ms
	m.wait = redial{}
	m.session = &MeshSession{name: m.c.name, relay: ms.open.ref, version: ms.open.ver, qc: ms.c.qc}
	m.sub, m.offered, m.txOK, m.fresh, m.tries, m.pending = subKeying, false, false, true, 0, nil
	if m.kT != nil {
		m.kT.Stop()
		m.kT = nil
	}
	if m.kst != kCalling {
		m.kst = kIdle
	}
	m.writePort()
	if !m.isUp {
		m.isUp, m.everUp = true, true
		m.toRoot(mChange{c: MeshChange{Name: m.c.name, Up: true}})
	}
	m.toRoot(mSession{s: m.session})
	m.syncSenders()
	m.stepKeys()
}

// msEnded takes the end of an MS: a failed Open, or the end of the session of the member.
func (m *mProc) msEnded(e msEnded) {
	switch e.ms {
	case m.opening:
		m.opening = nil
		m.dialFailed(e.err)
	case m.ms:
		m.ms, m.session = nil, nil
		m.downWhy = MeshLost
		if e.restart {
			m.downWhy = MeshRestart
		}
		m.drop()
		if m.ported {
			var b batch
			b.remove(dp.PortsKey{Port: m.c.port}.Entry(nil))
			if err := b.write(bg, m.r.cfg.Target); err != nil {
				slog.Error("Failed to delete the ports entry of a trunk", "relay", m.c.name, "error", err)
			}
			m.ported = false
		}
		if !m.ending {
			m.closing = true
			m.job(mJob{op: opClose, ms: e.ms})
			m.startDial()
		}
	}
}

// drop ends the P processes and the probe of the session, and deletes the trunk entries of the
// records and the member values: the routes go to other candidates.
func (m *mProc) drop() {
	for _, p := range m.senders {
		p.box.send(toEnd{})
	}
	for _, p := range m.receivers {
		p.box.send(toEnd{})
		m.stopWatch(p)
	}
	clear(m.senders)
	clear(m.receivers)
	clear(m.failed)
	for vpc := range m.parts {
		m.records(vpc, nil)
	}
	m.stopProbe()
	m.up().Delete(keyValues)
	m.sub = subKeying
}

// stopWatch ends the watch of the records of a receiving P.
func (m *mProc) stopWatch(p *pProc) {
	if stop := m.ps[p]; stop != nil {
		stop()
	}
}

// writePort writes the ports entry of the trunk for the session now.
func (m *mProc) writePort() {
	var b batch
	md := trunkKey(m.c.port)
	pa := dp.PortAction{Trunk: true, Session: m.ms.n, Addr: m.ms.open.psp, MTU: uint16(m.mtu()), MeterIndex: m.c.meter}
	if !m.metered {
		// The meter indices can have the config of an ended agent connection.
		b.meter(dp.MeterPort, m.c.meter, 0, 0)
		for lane := range uint32(dpLanes) {
			b.meter(dp.MeterLane, dpLanes*m.c.meter+lane, 0, 0)
		}
	}
	if m.ported {
		b.modify(dp.PortsKey{Port: m.c.port}.Entry(pa), md)
	} else {
		b.insert(dp.PortsKey{Port: m.c.port}.Entry(pa), md)
	}
	if err := b.write(bg, m.r.cfg.Target); err != nil {
		slog.Error("Failed to write the ports entry of a trunk", "relay", m.c.name, "error", err)
		return
	}
	m.ported, m.metered = true, true
}

// mtu returns the MTU of the trunk now. A new session at the same address keeps the last path.
func (m *mProc) mtu() int {
	switch {
	case m.sub == subFull:
		return trunkMTU
	case m.sub == subLimited:
		return trunkLimitedMTU
	case m.path == pathFull && m.ms != nil && m.pathTo == m.ms.open.psp:
		return trunkMTU
	}
	return trunkLimitedMTU
}

// end ends M: its MS and P processes end, its entries go, and its keys close.
func (m *mProc) end(e toMEnd) {
	if m.ending {
		return
	}
	m.ending, m.endDown = true, e.down
	m.cancel()
	if m.redialT != nil {
		m.redialT.Stop()
	}
	if m.kT != nil {
		m.kT.Stop()
	}
	for _, ms := range []*msProc{m.ms, m.opening} {
		if ms != nil {
			ms.box.send(msEnd{code: e.code, msg: e.msg})
		}
	}
	m.drop()
	if m.ported {
		var b batch
		b.remove(dp.PortsKey{Port: m.c.port}.Entry(nil))
		if err := b.write(bg, m.r.cfg.Target); err != nil {
			slog.Error("Failed to delete the ports entry of a trunk", "relay", m.c.name, "error", err)
		}
		m.ported = false
	}
	for _, j := range m.jobs {
		if j.res != nil {
			j.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "mesh session ended")}
		}
	}
	m.jobs = nil
	m.job(mJob{op: opClose})
}

// Keys.

// job queues a key operation, and sends the next one to the root when none runs.
func (m *mProc) job(j mJob) {
	m.jobs = append(m.jobs, j)
	m.nextJob()
}

func (m *mProc) nextJob() {
	if m.cur != nil || len(m.jobs) == 0 {
		return
	}
	j := m.jobs[0]
	m.jobs = m.jobs[1:]
	m.cur = &j
	var session uint64
	if j.ms != nil {
		session = j.ms.n
	}
	m.toRoot(mKeys{op: j.op, session: session, req: j.req, spis: j.spis})
}

// keysDone takes the result of the running key job.
func (m *mProc) keysDone(e toKeysDone) {
	j := m.cur
	if j == nil || j.op != e.op {
		return
	}
	m.cur = nil
	defer m.nextJob()
	switch j.op {
	case opClose:
		if m.ending {
			m.keysClosed = true
			return
		}
		if m.closing {
			m.closing = false
			if m.ms == nil && m.isUp {
				m.isUp = false
				slog.Info("Mesh member is down", "relay", m.c.name, "reason", m.downWhy.String())
				m.toRoot(mChange{c: MeshChange{Name: m.c.name, Down: m.downWhy}})
			}
		}
	case opApply:
		if e.err != nil {
			j.res <- callResult{err: e.err}
			return
		}
		j.res <- callResult{out: &dpv1.KeysResponse{RefusedSpis: e.refused}}
		if j.ms == m.ms && e.tx {
			m.txOK = true
			m.maybeProbe()
		}
	case opOffer, opRefused:
		if j.ms != m.ms || m.kst != kOffer {
			return
		}
		if e.err != nil {
			m.keysFailed(e.err)
			return
		}
		m.call(e.offer)
	}
}

// stepKeys gives the member the next key change: a new offer, or the oldest rekey that waits.
func (m *mProc) stepKeys() {
	if m.ms == nil || m.ending || m.kst != kIdle {
		return
	}
	switch {
	case m.fresh:
		m.fresh, m.tries, m.pending = false, 0, nil
		m.kst = kOffer
		m.job(mJob{op: opOffer, ms: m.ms})
	case m.offered && len(m.pending) > 0:
		req := m.pending[0]
		m.pending = m.pending[1:]
		m.call(req)
	}
}

// call gives req to the member in a TrunkKeys call task.
func (m *mProc) call(req keys.Request) {
	m.kst = kCalling
	ms := m.ms
	go func() {
		ctx, cancel := context.WithTimeout(ms.ctx, trunkKeysTimeout)
		defer cancel()
		res, err := ms.c.client.TrunkKeys(ctx, keyproto.ToProto(req))
		m.box.send(keysCalled{ms: ms, refused: res.GetRefusedSpis(), err: err})
	}()
}

// keysCalled takes the answer of the member to a key change. The member refuses an SPI that it
// holds from another receiver, and gets a new SA for it.
func (m *mProc) keysCalled(e keysCalled) {
	if m.kst == kCalling {
		m.kst = kIdle
	}
	if e.ms != m.ms || m.ending {
		m.stepKeys()
		return
	}
	if e.err != nil && e.ms.ctx.Err() != nil {
		// The session ends: msEnded comes next.
		return
	}
	if e.err != nil {
		m.keysFailed(e.err)
		return
	}
	if len(e.refused) > 0 {
		if m.tries++; m.tries > maxClashes {
			m.keysFailed(errors.New("member refused the SPIs of each offer"))
			return
		}
		m.kst = kOffer
		m.job(mJob{op: opRefused, ms: m.ms, spis: e.refused})
		return
	}
	m.tries = 0
	m.kwait = redial{}
	m.offered = true
	m.maybeProbe()
	m.stepKeys()
}

// keysFailed waits before a new offer: the member can have a part of the keys.
func (m *mProc) keysFailed(err error) {
	if rpc.CodeOf(err) == rpc.Unimplemented {
		slog.Info("Mesh member has no trunk", "relay", m.c.name)
		m.kst = kWaiting
		return
	}
	if m.kwait.wait == 0 {
		slog.Warn("Failed to give trunk keys to a mesh member", "relay", m.c.name, "error", err)
	} else {
		slog.Debug("Failed to give trunk keys to a mesh member", "relay", m.c.name, "error", err)
	}
	m.kst, m.fresh = kWaiting, true
	ms := m.ms
	m.kT = time.AfterFunc(m.kwait.next(), func() { m.box.send(keysRetry{ms: ms}) })
}

// Probes.

// maybeProbe starts the probes when each relay gave its keys on the session.
func (m *mProc) maybeProbe() {
	if m.ms != nil && m.offered && m.txOK && m.sub == subKeying {
		m.sub = subProbing
		m.startProbe()
	}
}

// startProbe starts a probe run: full-size trunk messages 300 ms apart.
func (m *mProc) startProbe() {
	m.stopProbe()
	run := &probeRun{ms: m.ms}
	_, _ = rand.Read(run.id[:])
	m.run = run
	run.wait = time.AfterFunc(trunkProbeWait, func() { m.box.send(probeWait{run: run}) })
	m.probeTick(run)
}

func (m *mProc) probeTick(run *probeRun) {
	if run != m.run || m.sub != subProbing || run.round >= trunkProbeRounds {
		return
	}
	run.round++
	msg := make([]byte, trunkMTU)
	msg[0] = trunkMsgProbe
	copy(msg[1:], run.id[:])
	m.seal(msg)
	if run.round < trunkProbeRounds {
		run.tick = time.AfterFunc(trunkProbeInterval, func() { m.box.send(probeTick{run: run}) })
	}
}

// stopProbe stops the timers of the probe run and of its retry.
func (m *mProc) stopProbe() {
	if run := m.run; run != nil {
		if run.tick != nil {
			run.tick.Stop()
		}
		run.wait.Stop()
	}
	if m.retryT != nil {
		m.retryT.Stop()
		m.retryT = nil
	}
}

// probed keeps the result of the probe run: the trunk MTU, and the member values for V.
func (m *mProc) probed(ok bool) {
	m.stopProbe()
	old := m.path
	m.sub, m.path, m.pathTo = subLimited, pathLimited, m.ms.open.psp
	if ok {
		m.sub, m.path = subFull, pathFull
	}
	if m.path != old {
		if ok {
			slog.Info("Trunk path carries full-size packets", "relay", m.c.name, "mtu", trunkMTU)
		} else {
			slog.Warn("Trunk path does not carry full-size packets", "relay", m.c.name, "mtu", trunkLimitedMTU)
		}
	}
	m.writePort()
	if !ok {
		run := m.run
		m.retryT = time.AfterFunc(trunkProbeRetry, func() { m.box.send(probeAgain{run: run}) })
	}
	m.ver++
	store(m.up(), keyValues, &memberValues{inc: m.c.inc, ver: m.ver, ref: m.ms.open.ref, port: m.c.port, cell: m.c.cell, mtu: m.mtu()})
}

// seal sends msg, a message of this relay with tag 0, to the member.
func (m *mProc) seal(msg []byte) {
	po := &p4.PacketOut{Payload: msg, Metadata: dp.PacketOutMeta{Kind: dp.KindSeal, Port: m.c.port, Session: m.ms.n}.Metadata()}
	if err := m.r.cfg.Target.PacketOut(po); err != nil {
		slog.Debug("Failed to send a trunk message", "relay", m.c.name, "error", err)
	}
}

// packetIn takes a message of the member itself: a full-size probe, which gets an answer of the
// same size, or the answer to a probe of this relay.
func (m *mProc) packetIn(pin packetIn) {
	msg := pin.payload
	if m.ms == nil || pin.md.session != m.ms.n || pin.md.kind != dp.KindPunt || len(msg) < trunkProbeLen {
		return
	}
	switch msg[0] {
	case trunkMsgProbe:
		if m.answers.Allow() {
			msg[0] = trunkMsgReply
			m.seal(msg)
		}
	case trunkMsgReply:
		run := m.run
		if run != nil && m.sub == subProbing && len(msg) == trunkMTU && [trunkProbeLen - 1]byte(msg[1:trunkProbeLen]) == run.id {
			m.probed(true)
		}
	}
}

// Presence.

// setsChanged gives the new announcement sets to the sending P of their tenant.
func (m *mProc) setsChanged(keys []string) {
	for _, k := range keys {
		project, _, ok := strings.Cut(strings.TrimPrefix(k, keySet), "/")
		if !ok {
			continue
		}
		if p := m.senders[project]; p != nil {
			if set := load[*annSet](m.c.down, k); set != nil {
				store(p.down, k, set)
			} else {
				p.down.Delete(k)
			}
		}
	}
	m.syncSenders()
}

// tenants returns the tenants with announcements.
func (m *mProc) tenants() map[string]bool {
	out := map[string]bool{}
	for _, v := range m.c.down.LoadAll() {
		if set, _ := v.p.(*annSet); set != nil && len(set.entries) > 0 {
			out[set.vpc.Project] = true
		}
	}
	return out
}

// syncSenders keeps one sending P for each tenant with announcements on the session.
func (m *mProc) syncSenders() {
	if m.ms == nil || m.ending {
		return
	}
	want := m.tenants()
	for tenant, p := range m.senders {
		if !want[tenant] {
			p.box.send(toEnd{})
			delete(m.senders, tenant)
		}
	}
	for tenant := range want {
		if m.senders[tenant] != nil || m.failed[tenant] {
			continue
		}
		down := &valueMap{}
		for k, v := range m.c.down.LoadAll() {
			if set, _ := v.p.(*annSet); set != nil && set.vpc.Project == tenant {
				down.Store(k, v)
			}
		}
		p := startSend(m.box, m.ms, tenant, down)
		m.senders[tenant] = p
		m.ps[p] = nil
	}
}

// incoming starts a receiving P for an incoming call. A new call of a tenant ends the old one.
func (m *mProc) incoming(e mIncoming) {
	if e.ms != m.ms || m.ending {
		e.done <- rpc.Errorf(rpc.Unavailable, "mesh session is not the session of the member now")
		return
	}
	if old := m.receivers[e.tenant]; old != nil {
		old.box.send(toEnd{})
		m.stopWatch(old)
		m.dropTenant(e.tenant)
	}
	p := startReceive(m.box, e.ms, e.tenant, e.st, e.first, e.done)
	m.receivers[e.tenant] = p
	ctx, cancel := context.WithCancel(m.ctx)
	m.ps[p] = cancel
	watch(ctx, p.up, func(keys []string) { m.box.send(pChanged{p: p, keys: keys}) })
}

// dropTenant deletes the records of each VPC of tenant.
func (m *mProc) dropTenant(tenant string) {
	for vpc := range m.parts {
		if vpc.Project == tenant {
			m.records(vpc, nil)
		}
	}
}

func (m *mProc) pEnded(e pEnded) {
	p := e.p
	if stop := m.ps[p]; stop != nil {
		stop()
	}
	delete(m.ps, p)
	if m.receivers[p.tenant] == p {
		delete(m.receivers, p.tenant)
		m.dropTenant(p.tenant)
	}
	if m.senders[p.tenant] != p {
		return
	}
	// The call ended by itself. After a stall, M opens it again at once, with the full VPC list
	// and the full sets. After a different cause, the tenant gets no call until the next MS.
	delete(m.senders, p.tenant)
	if m.ms != p.ms {
		return
	}
	if !e.stalled {
		slog.Warn("Failed to send attachments to a mesh member", "relay", m.c.name, "tenant", p.tenant, "error", e.err)
		m.failed[p.tenant] = true
		return
	}
	m.syncSenders()
}

// records makes the trunk entries of vpc match the records rs, then stores the part of vpc for
// the root. A nil rs deletes them.
func (m *mProc) records(vpc VPCKey, rs *recordSet) {
	if rs != nil && len(rs.recs) == 0 {
		rs = nil
	}
	old := m.parts[vpc]
	touched := map[uint32]bool{}
	if len(m.tags) == 0 && m.ms != nil {
		// The entries of the records are all of one session.
		m.tagSession = m.ms.n
	}
	if old != nil {
		for id, rec := range old.recs {
			if rs == nil || rs.recs[id] != rec {
				m.unref(rec, touched)
			}
		}
	}
	if rs != nil {
		for id, rec := range rs.recs {
			if old == nil || old.recs[id] != rec {
				m.ref(rec, touched)
			}
		}
	}
	m.writeTags(touched)
	key := setKey(keyPart, vpc)
	if rs == nil {
		delete(m.parts, vpc)
		m.up().Delete(key)
		return
	}
	m.parts[vpc] = rs
	store(m.up(), key, rs)
}

// ref adds rec to the entries of its tag. A tag names one VPC: a record of another VPC with that
// tag gets no entries.
func (m *mProc) ref(rec *record, touched map[uint32]bool) {
	name := vpcName(rec.vpc, rec.networkID)
	ts := m.tags[rec.tag]
	if ts == nil {
		ts = &tagState{name: name, vni: rec.networkID, recs: map[*record]struct{}{}, refs: map[netip.Prefix]int{}, sources: map[netip.Prefix]struct{}{}}
		m.tags[rec.tag] = ts
	}
	if ts.name != name {
		slog.Warn("Refused an announcement of a mesh member with the tag of another VPC", "relay", m.c.name, "tag", rec.tag, "attachment", rec.id)
		return
	}
	ts.recs[rec] = struct{}{}
	for _, p := range rec.prefixes {
		ts.refs[p]++
	}
	touched[rec.tag] = true
}

func (m *mProc) unref(rec *record, touched map[uint32]bool) {
	ts := m.tags[rec.tag]
	if ts == nil {
		return
	}
	if _, ok := ts.recs[rec]; !ok {
		return
	}
	delete(ts.recs, rec)
	for _, p := range rec.prefixes {
		if ts.refs[p]--; ts.refs[p] <= 0 {
			delete(ts.refs, p)
		}
	}
	touched[rec.tag] = true
}

// writeTags writes the classify and source entries of the touched tags in one Write.
func (m *mProc) writeTags(touched map[uint32]bool) {
	if len(touched) == 0 {
		return
	}
	var b batch
	md := trunkKey(m.c.port)
	type next struct {
		classify bool
		sources  map[netip.Prefix]struct{}
	}
	nexts := map[uint32]next{}
	tags := make([]uint32, 0, len(touched))
	for tag := range touched {
		tags = append(tags, tag)
	}
	slices.Sort(tags)
	session := m.tagSession
	for _, tag := range tags {
		ts := m.tags[tag]
		want := next{classify: len(ts.recs) > 0 && m.ms != nil && m.ms.n == session, sources: map[netip.Prefix]struct{}{}}
		if want.classify {
			for p := range ts.refs {
				want.sources[p] = struct{}{}
			}
		}
		key := dp.ClassifyKey{Port: m.c.port, Session: session, Tag: tag}
		switch {
		case want.classify && !ts.classify:
			b.insert(key.Entry(dp.ContextAction{VPC: ts.name, VNI: ts.vni, Cell: m.c.cell}), md)
		case !want.classify && ts.classify:
			b.remove(key.Entry(nil))
		}
		for p := range want.sources {
			if _, ok := ts.sources[p]; !ok {
				b.insert(dp.SourceKey{Port: m.c.port, Session: session, Tag: tag, Src: p}.Entry(dp.NoAction{}), md)
			}
		}
		for p := range ts.sources {
			if _, ok := want.sources[p]; !ok {
				b.remove(dp.SourceKey{Port: m.c.port, Session: session, Tag: tag, Src: p}.Entry(nil))
			}
		}
		nexts[tag] = want
	}
	if err := b.write(bg, m.r.cfg.Target); err != nil {
		slog.Error("Failed to write the entries of the records of a mesh member", "relay", m.c.name, "error", err)
		return
	}
	for tag, n := range nexts {
		ts := m.tags[tag]
		ts.classify, ts.sources = n.classify, n.sources
		if len(ts.recs) == 0 {
			delete(m.tags, tag)
		}
	}
}

// fetch gets the host snapshot of the member in a task.
func (m *mProc) fetch(n uint64) {
	if m.ms == nil || m.ending {
		m.toRoot(mFetched{n: n, err: rpc.Errorf(rpc.NotFound, "member has no open session")})
		return
	}
	m.fetches++
	client := m.ms.c.client
	go func() {
		data, err := fetchSnapshot(m.ctx, client)
		m.box.send(fetchDone{n: n, data: data, err: err})
	}()
}

// redial gives the waits before the dials of one member.
type redial struct{ wait time.Duration }

// next returns the wait before the next dial. The random part stops the relays from dialing all
// at one time.
func (b *redial) next() time.Duration {
	b.wait = min(max(2*b.wait, redialMin), redialMax)
	return b.wait + mrand.N(b.wait/2+1)
}

// trunkKey is the writer key of the entries of a trunk port.
func trunkKey(port uint64) string { return fmt.Sprintf("t/%d", port) }
