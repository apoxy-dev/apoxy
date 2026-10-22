// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// maxPresenceEntries is the most announcements of one PresenceUpdate.
	maxPresenceEntries = 256
	// maxPresenceParts is the most parts, or VPCs of the list, of one PresenceUpdate.
	maxPresenceParts = 4096
	// maxPresenceBytes is the most bytes of one PresenceUpdate.
	maxPresenceBytes = 1 << 20
	// maxPartEntries is the most announcements of one part, so that each VPC gets a turn.
	maxPartEntries = 64
	// maxUnacked is the most bytes of a call that the receiver did not ack.
	maxUnacked = 1 << 20
	// maxWriter is the most messages of a call in its writer.
	maxWriter = 2
	// maxNotTaken is the most messages of a call that the receiving P did not take in.
	maxNotTaken = 8
	// presenceStall is the time that a message waits for its ack. Then the call ends.
	presenceStall = 5 * time.Second
	// maxAttachmentID is the most bytes of an attachment ID from a member.
	maxAttachmentID = 128
	// keyRecords is the prefix of the keys of the records of a VPC in the up map of a receiving P.
	keyRecords = "rec/"
	// keySet is the prefix of the keys of the announcement set of a VPC in the maps of M and P.
	keySet = "set/"
)

// setKey returns the key of a value of the VPC vpc in a map, with prefix.
func setKey(prefix string, vpc VPCKey) string { return prefix + vpc.Project + "/" + vpc.UID }

// presenceServer is the called end of a Presence call.
type presenceServer = rpc.BidiStreamServer[dpv1.PresenceUpdate, dpv1.PresenceControl]

// annSet is the announcement set of one VPC: one entry for each attachment of this relay, by ID.
// It is immutable, and a changed entry is a new pointer.
type annSet struct {
	vpc     VPCKey
	entries map[string]*dpv1.Presence
}

// record is one checked announcement of a member: one attachment of another relay. It is
// immutable.
type record struct {
	id        string
	gen       uint64
	attached  uint64
	vpc       VPCKey
	networkID uint32
	subject   string
	agent     string
	instance  uint64
	rank      uint32
	state     dpv1.AnnouncerState
	// activeFrom is the end of the hold time, or the zero time.
	activeFrom time.Time
	// tag is the session tag of the agent connection on the member.
	tag      uint32
	prefixes []netip.Prefix
}

// recordSet is the records of one VPC from one call, by attachment ID. It is immutable.
type recordSet struct {
	vpc  VPCKey
	recs map[string]*record
}

// checkPresence checks the form of one entry of a member in a part of vpc, and returns its record.
// A gone entry has only the attachment ID and the generation.
func checkPresence(vpc VPCKey, e *dpv1.Presence) (*record, bool, error) {
	rec := &record{id: e.GetAttachmentId(), gen: e.GetGeneration(), vpc: vpc}
	switch {
	case rec.id == "" || len(rec.id) > maxAttachmentID:
		return nil, false, fmt.Errorf("attachment ID has %d bytes", len(rec.id))
	case rec.gen == 0:
		return nil, false, errors.New("no generation")
	case e.GetGone():
		return rec, true, nil
	case len(e.GetPrefixes()) > maxEntryPrefixes:
		return nil, false, fmt.Errorf("%d prefixes, which is more than the limit %d", len(e.GetPrefixes()), maxEntryPrefixes)
	}
	key, err := KeyOf(e.GetVpc())
	if err != nil {
		return nil, false, err
	}
	if key != vpc {
		return nil, false, fmt.Errorf("VPC %s/%s is not the VPC of the part", key.Project, key.UID)
	}
	if rec.networkID = e.GetVpc().GetNetworkId(); rec.networkID > pspwire.MaxVNI {
		return nil, false, fmt.Errorf("network ID %d is above %d", rec.networkID, pspwire.MaxVNI)
	}
	// The subject names its VPC, so an entry cannot put an agent in another VPC.
	id, err := identity.ParseID(e.GetSubject())
	if err != nil {
		return nil, false, fmt.Errorf("subject: %w", err)
	}
	if id.Project != vpc.Project || id.VPC != vpc.UID {
		return nil, false, fmt.Errorf("subject %q is not in VPC %s/%s", e.GetSubject(), vpc.Project, vpc.UID)
	}
	rec.subject, rec.agent, rec.instance, rec.rank = e.GetSubject(), e.GetAgentName(), e.GetInstance(), e.GetRank()
	// A state that this build does not know stays: it ranks after the known ones.
	rec.state = e.GetState()
	if rec.attached = e.GetAttached(); rec.attached > rec.gen {
		return nil, false, fmt.Errorf("attach generation %d is above the generation %d", rec.attached, rec.gen)
	}
	if rec.attached == 0 {
		rec.attached = rec.gen
	}
	if t := e.GetActiveFrom(); t != nil {
		if err := t.CheckValid(); err != nil {
			return nil, false, fmt.Errorf("active_from: %w", err)
		}
		rec.activeFrom = t.AsTime()
	}
	if rec.tag = e.GetSenderTag(); rec.tag == 0 || rec.tag > pspwire.MaxVNI {
		return nil, false, fmt.Errorf("sender tag %d is not from 1 to %d", rec.tag, pspwire.MaxVNI)
	}
	for _, t := range e.GetPrefixes() {
		px, err := netip.ParsePrefix(t)
		if err != nil {
			return nil, false, fmt.Errorf("prefix: %w", err)
		}
		rec.prefixes = append(rec.prefixes, px.Masked())
	}
	return rec, false, nil
}

// announcement returns the entry of the attachment id of this relay in vpc, with the prefixes ps,
// the candidate c and the session tag of its connection.
func announcement(vpc *dpv1.VPCRef, id string, ps []netip.Prefix, c *candidate, tag uint32, gen uint64) *dpv1.Presence {
	e := &dpv1.Presence{
		Vpc:          vpc,
		AttachmentId: id,
		Generation:   gen,
		Subject:      c.agent.id,
		AgentName:    c.agent.name,
		SenderTag:    tag,
		Instance:     c.agent.instance,
		State:        c.state,
		Rank:         c.rank,
		Attached:     c.attached,
	}
	if !c.activeFrom.IsZero() {
		e.ActiveFrom = timestamppb.New(c.activeFrom)
	}
	for _, p := range ps {
		e.Prefixes = append(e.Prefixes, p.String())
	}
	return e
}

// fitsOneMessage reports whether the announcement e fits in one PresenceUpdate.
func fitsOneMessage(e *dpv1.Presence) bool {
	u := &dpv1.PresenceUpdate{Seq: 1 << 63, Parts: []*dpv1.PresencePart{{Vpc: e.GetVpc(), EndOfFullSet: true, Entries: []*dpv1.Presence{e}}}}
	return proto.Size(u) <= maxPresenceBytes
}

// Events of P from its tasks.
type (
	callOpened struct {
		st  rpc.BidiStreamClient[dpv1.PresenceUpdate, dpv1.PresenceControl]
		err error
	}
	acked       struct{ seq uint64 }
	written     struct{}
	stallEv     struct{}
	updateIn    struct{ u *dpv1.PresenceUpdate }
	ackWritten  struct{}
	pReaderDone struct{ err error }
	pWriterDone struct{ err error }
)

// pProc is the process P of one Presence call: one tenant, one direction, one MS.
type pProc struct {
	mbox   *mailbox // The mailbox of M.
	box    *mailbox
	ms     *msProc
	tenant string
	send   bool
	ctx    context.Context
	cancel context.CancelFunc
	down   *valueMap // Sending: the announcement sets of the VPCs of the tenant, from M.
	up     *valueMap // Receiving: the records of each VPC, to M.

	readerOn, writerOn bool
	ending             bool
	err                error
	stalled            bool // The call ended with no ack in time.

	// Sending.
	client  dpv1.MeshClient
	out     chan *dpv1.PresenceUpdate
	opening bool
	seq     uint64
	inW     int
	unacked []sentMsg
	bytes   int
	stall   *time.Timer
	listed  bool     // end_of_vpcs is sent.
	list    []VPCKey // VPCs of the list that are not sent yet.
	vpcs    map[VPCKey]*outVPC
	turn    []VPCKey // The order of the VPCs for parts.

	// Receiving.
	st      presenceServer
	first   *dpv1.PresenceUpdate
	done    chan error
	sem     chan struct{}
	lastSeq uint64
	endList bool
	recs    map[VPCKey]map[string]*record
	ackWant uint64
	ackOn   bool
	ackOut  chan uint64
}

// sentMsg is a message that waits for its ack.
type sentMsg struct {
	seq  uint64
	size int
	at   time.Time
}

// outVPC is the send state of one VPC on a call.
type outVPC struct {
	set  *annSet
	sent map[string]*dpv1.Presence // What the receiver has.
	pend []string                  // IDs whose entry differs from sent.
	full bool                      // end_of_full_set is sent.
}

// pEnded tells M that P ended.
type pEnded struct {
	p       *pProc
	err     error
	stalled bool
}

// pChanged tells M that the records of a receiving P changed.
type pChanged struct {
	p    *pProc
	keys []string
}

// startSend starts a sending P for tenant on the session ms. down has the announcement sets.
func startSend(mbox *mailbox, ms *msProc, tenant string, down *valueMap) *pProc {
	ctx, cancel := context.WithCancel(ms.ctx)
	p := &pProc{
		mbox: mbox, box: newMailbox(0), ms: ms, tenant: tenant, send: true, ctx: ctx, cancel: cancel,
		down: down, client: ms.c.client, vpcs: map[VPCKey]*outVPC{},
	}
	watch(ctx, down, func(keys []string) { p.box.send(valuesChanged{keys: keys}) })
	go p.run()
	return p
}

// startReceive starts a receiving P for the incoming call st of tenant, whose first message is
// first. done gets the status of the call at the end of P.
func startReceive(mbox *mailbox, ms *msProc, tenant string, st presenceServer, first *dpv1.PresenceUpdate, done chan error) *pProc {
	ctx, cancel := context.WithCancel(ms.ctx)
	p := &pProc{
		mbox: mbox, box: newMailbox(0), ms: ms, tenant: tenant, ctx: ctx, cancel: cancel, up: &valueMap{},
		st: st, first: first, done: done, sem: make(chan struct{}, maxNotTaken),
		recs: map[VPCKey]map[string]*record{}, ackOut: make(chan uint64, 1),
	}
	go p.run()
	return p
}

func (p *pProc) run() {
	if p.send {
		p.opening = true
		go func() {
			st, err := p.client.Presence(p.ctx)
			p.box.send(callOpened{st: st, err: err})
		}()
	} else {
		p.readerOn, p.writerOn = true, true
		p.sem <- struct{}{}
		p.box.send(updateIn{u: p.first})
		go p.read()
		go p.writeAcks(p.ackOut)
	}
	for {
		for _, e := range p.box.take() {
			p.handle(e)
		}
		if !p.ending && p.send {
			p.fill(time.Now())
		}
		// The handler of an incoming call returns after the ack writer stopped, and its return
		// ends the read of the call.
		if p.ending && p.done != nil && !p.writerOn {
			p.done <- p.err
			p.done = nil
		}
		if p.ending && !p.readerOn && !p.writerOn && !p.opening {
			break
		}
		var stop <-chan struct{}
		if !p.ending {
			stop = p.ctx.Done()
		}
		select {
		case <-p.box.sig:
		case <-stop:
			p.end(nil)
		}
	}
	if p.stall != nil {
		p.stall.Stop()
	}
	p.box.close()
	p.mbox.send(pEnded{p: p, err: p.err, stalled: p.stalled})
}

// end ends the call: the context of the call ends, and P waits for its tasks.
func (p *pProc) end(err error) {
	if p.ending {
		return
	}
	p.ending, p.err = true, err
	p.cancel()
	if p.out != nil {
		close(p.out)
		p.out = nil
	}
	if !p.send && p.ackOut != nil {
		close(p.ackOut)
		p.ackOut = nil
	}
}

func (p *pProc) handle(e any) {
	switch e := e.(type) {
	case toEnd:
		p.end(nil)
	case callOpened:
		p.opening = false
		if e.err != nil {
			p.end(e.err)
			return
		}
		if p.ending {
			return
		}
		p.out = make(chan *dpv1.PresenceUpdate, maxWriter)
		p.readerOn, p.writerOn = true, true
		go p.readAcks(e.st)
		go p.writeUpdates(e.st, p.out)
		p.startList()
	case valuesChanged:
		p.setsChanged(e.keys)
	case acked:
		p.acked(e.seq, time.Now())
	case written:
		p.inW--
	case stallEv:
		if len(p.unacked) > 0 && !time.Now().Before(p.unacked[0].at.Add(presenceStall)) {
			slog.Warn("Ended a Presence call with no ack", "relay", p.ms.name, "tenant", p.tenant, "seq", p.unacked[0].seq)
			p.stalled = !p.ending
			p.end(rpc.Errorf(rpc.DeadlineExceeded, "no ack for %v", presenceStall))
		}
	case updateIn:
		if !p.ending {
			if err := p.take(e.u); err != nil {
				slog.Warn("Ended an incoming Presence call", "relay", p.ms.name, "tenant", p.tenant, "error", err)
				p.end(err)
			}
		}
		<-p.sem
	case ackWritten:
		p.ackOn = false
		p.sendAck()
	case pReaderDone:
		p.readerOn = false
		if errors.Is(e.err, io.EOF) {
			e.err = nil
		}
		p.end(e.err)
	case pWriterDone:
		p.writerOn = false
		p.end(e.err)
	}
}

// Sending P.

// startList takes the VPCs of the tenant that have announcements: the first message lists them.
func (p *pProc) startList() {
	p.setsChanged(nil)
	for vpc, o := range p.vpcs {
		if len(o.set.entries) > 0 {
			p.list = append(p.list, vpc)
		}
	}
	slices.SortFunc(p.list, func(a, b VPCKey) int { return compareKey(a, b) })
	if len(p.list) == 0 {
		p.end(nil)
	}
}

func compareKey(a, b VPCKey) int {
	if a.Project != b.Project {
		if a.Project < b.Project {
			return -1
		}
		return 1
	}
	switch {
	case a.UID < b.UID:
		return -1
	case a.UID > b.UID:
		return 1
	}
	return 0
}

// setsChanged loads the new announcement sets, and finds the changes to send for each. Nil keys
// loads each set.
func (p *pProc) setsChanged(keys []string) {
	if keys == nil {
		for k := range p.down.LoadAll() {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		set := load[*annSet](p.down, k)
		if set == nil {
			// A deleted set is an empty set: its announcements go.
			vpc, ok := keyVPC(keySet, k)
			if !ok {
				continue
			}
			set = &annSet{vpc: vpc}
		}
		o := p.vpcs[set.vpc]
		if o == nil {
			o = &outVPC{sent: map[string]*dpv1.Presence{}}
			p.vpcs[set.vpc] = o
			p.turn = append(p.turn, set.vpc)
		}
		o.set = set
		o.pend = o.pend[:0]
		for id, e := range set.entries {
			if o.sent[id] != e {
				o.pend = append(o.pend, id)
			}
		}
		for id := range o.sent {
			if _, ok := set.entries[id]; !ok {
				o.pend = append(o.pend, id)
			}
		}
		slices.Sort(o.pend)
	}
}

// fill gives the writer the next messages, within the limits of the flow control.
func (p *pProc) fill(now time.Time) {
	for p.out != nil && p.inW < maxWriter && p.bytes < maxUnacked {
		u := p.next()
		if u == nil {
			return
		}
		p.seq++
		u.Seq = p.seq
		size := proto.Size(u)
		p.inW++
		p.bytes += size
		p.unacked = append(p.unacked, sentMsg{seq: u.Seq, size: size, at: now})
		if len(p.unacked) == 1 {
			p.armStall(now)
		}
		p.out <- u
	}
}

// next returns the next message: the list of VPCs first, then one part of each VPC with changes
// in turn. It returns nil when nothing waits.
func (p *pProc) next() *dpv1.PresenceUpdate {
	u := &dpv1.PresenceUpdate{}
	if !p.listed {
		n := 0
		for len(p.list) > 0 && len(u.Vpcs) < maxPresenceParts {
			k := p.list[0]
			ref := &dpv1.VPCRef{ProjectId: k.Project, VpcUid: k.UID}
			if n += proto.Size(ref) + 8; n > maxPresenceBytes-1024 {
				break
			}
			u.Vpcs = append(u.Vpcs, ref)
			p.list = p.list[1:]
		}
		if len(p.list) == 0 {
			u.EndOfVpcs, p.listed = true, true
		}
		return u
	}
	entries, size := 0, 0
	var keep, done []VPCKey
	for i, vpc := range p.turn {
		o := p.vpcs[vpc]
		if len(o.pend) == 0 && o.full {
			if len(o.sent) == 0 && len(o.set.entries) == 0 {
				delete(p.vpcs, vpc)
				continue
			}
			keep = append(keep, vpc)
			continue
		}
		if entries >= maxPresenceEntries || len(u.Parts) >= maxPresenceParts || size >= maxPresenceBytes-4096 {
			keep = append(keep, p.turn[i:]...)
			break
		}
		part := &dpv1.PresencePart{Vpc: &dpv1.VPCRef{ProjectId: vpc.Project, VpcUid: vpc.UID}}
		for len(o.pend) > 0 && len(part.Entries) < maxPartEntries && entries < maxPresenceEntries {
			id := o.pend[0]
			e := o.set.entries[id]
			if e == nil {
				old := o.sent[id]
				e = &dpv1.Presence{AttachmentId: id, Generation: old.GetGeneration() + 1, Gone: true}
			}
			n := proto.Size(e) + 8
			if size+n > maxPresenceBytes-4096 && entries > 0 {
				break
			}
			o.pend = o.pend[1:]
			if e.GetGone() {
				delete(o.sent, id)
			} else {
				o.sent[id] = e
			}
			part.Entries = append(part.Entries, e)
			entries++
			size += n
		}
		if len(o.pend) == 0 && !o.full {
			part.EndOfFullSet, o.full = true, true
		}
		u.Parts = append(u.Parts, part)
		size += proto.Size(part.Vpc) + 8
		done = append(done, vpc)
	}
	// A VPC that sent a part goes to the end of the turn.
	p.turn = append(keep, done...)
	if len(u.Parts) == 0 {
		return nil
	}
	return u
}

func (p *pProc) armStall(now time.Time) {
	d := p.unacked[0].at.Add(presenceStall).Sub(now)
	if p.stall == nil {
		p.stall = time.AfterFunc(d, func() { p.box.send(stallEv{}) })
		return
	}
	p.stall.Reset(d)
}

// acked takes the ack of the receiver: each message up to seq is out of the flow control.
func (p *pProc) acked(seq uint64, now time.Time) {
	if seq > p.seq {
		p.end(rpc.Errorf(rpc.InvalidArgument, "ack %d is above the last seq %d", seq, p.seq))
		return
	}
	for len(p.unacked) > 0 && p.unacked[0].seq <= seq {
		p.bytes -= p.unacked[0].size
		p.unacked = p.unacked[1:]
	}
	if len(p.unacked) > 0 {
		p.armStall(now)
	} else if p.stall != nil {
		p.stall.Stop()
	}
}

// readAcks reads the acks of the receiver until the call ends.
func (p *pProc) readAcks(st rpc.BidiStreamClient[dpv1.PresenceUpdate, dpv1.PresenceControl]) {
	for {
		c, err := st.Recv()
		if err != nil {
			p.box.send(pReaderDone{err: err})
			return
		}
		p.box.send(acked{seq: c.GetAck()})
	}
}

// writeUpdates sends the messages of out until out closes, then closes the send side.
func (p *pProc) writeUpdates(st rpc.BidiStreamClient[dpv1.PresenceUpdate, dpv1.PresenceControl], out chan *dpv1.PresenceUpdate) {
	for u := range out {
		if err := st.Send(u); err != nil {
			p.box.send(pWriterDone{err: err})
			for range out {
			}
			return
		}
		p.box.send(written{})
	}
	_ = st.CloseSend()
	p.box.send(pWriterDone{})
}

// Receiving P.

// read reads the messages of the caller, at most maxNotTaken ahead of P, until the call ends.
func (p *pProc) read() {
	for {
		select {
		case p.sem <- struct{}{}:
		case <-p.ctx.Done():
			p.box.send(pReaderDone{})
			return
		}
		u, err := p.st.Recv()
		if err != nil {
			<-p.sem
			p.box.send(pReaderDone{err: err})
			return
		}
		p.box.send(updateIn{u: u})
	}
}

// writeAcks sends the acks of P until P ends.
func (p *pProc) writeAcks(acks chan uint64) {
	for seq := range acks {
		if err := p.st.Send(&dpv1.PresenceControl{Ack: seq}); err != nil {
			p.box.send(pWriterDone{err: err})
			for range acks {
			}
			return
		}
		p.box.send(ackWritten{})
	}
	p.box.send(pWriterDone{})
}

// sendAck gives the writer the newest ack when it has no ack in flight.
func (p *pProc) sendAck() {
	if p.ackOn || p.ackOut == nil || p.ackWant == 0 {
		return
	}
	p.ackOn = true
	p.ackOut <- p.ackWant
	p.ackWant = 0
}

// take checks one message of the caller, stores the records of its parts for M, and acks it.
func (p *pProc) take(u *dpv1.PresenceUpdate) error {
	if u.GetSeq() != p.lastSeq+1 {
		return rpc.Errorf(rpc.InvalidArgument, "seq %d after %d", u.GetSeq(), p.lastSeq)
	}
	p.lastSeq = u.GetSeq()
	switch {
	case len(u.GetVpcs()) > maxPresenceParts || len(u.GetParts()) > maxPresenceParts:
		return rpc.Errorf(rpc.InvalidArgument, "message has more than %d VPCs or parts", maxPresenceParts)
	case proto.Size(u) > maxPresenceBytes:
		return rpc.Errorf(rpc.InvalidArgument, "message has more than %d bytes", maxPresenceBytes)
	case p.endList && (len(u.GetVpcs()) > 0 || u.GetEndOfVpcs()):
		return rpc.Errorf(rpc.InvalidArgument, "VPC list after its end")
	case !p.endList && len(u.GetParts()) > 0:
		return rpc.Errorf(rpc.InvalidArgument, "part before the end of the VPC list")
	}
	for _, ref := range u.GetVpcs() {
		if _, err := p.tenantKey(ref); err != nil {
			return err
		}
	}
	p.endList = p.endList || u.GetEndOfVpcs()
	entries := 0
	seen := map[VPCKey]bool{}
	for _, part := range u.GetParts() {
		entries += len(part.GetEntries())
		vpc, err := p.tenantKey(part.GetVpc())
		switch {
		case err != nil:
			return err
		case seen[vpc]:
			return rpc.Errorf(rpc.InvalidArgument, "two parts of VPC %s/%s in one message", vpc.Project, vpc.UID)
		case len(part.GetEntries()) > maxPartEntries:
			return rpc.Errorf(rpc.InvalidArgument, "part has more than %d announcements", maxPartEntries)
		case entries > maxPresenceEntries:
			return rpc.Errorf(rpc.InvalidArgument, "message has more than %d announcements", maxPresenceEntries)
		}
		seen[vpc] = true
	}
	for _, part := range u.GetParts() {
		vpc, _ := p.tenantKey(part.GetVpc())
		p.apply(vpc, part.GetEntries())
	}
	p.ackWant = u.GetSeq()
	p.sendAck()
	return nil
}

// tenantKey returns the key of a VPC of the tenant of the call.
func (p *pProc) tenantKey(ref *dpv1.VPCRef) (VPCKey, error) {
	k, err := KeyOf(ref)
	if err != nil {
		return VPCKey{}, err
	}
	if k.Project != p.tenant {
		return VPCKey{}, rpc.Errorf(rpc.PermissionDenied, "VPC %s/%s is not of the tenant %s of the call", k.Project, k.UID, p.tenant)
	}
	return k, nil
}

// apply applies the entries of one part of vpc and stores the new records of vpc for M. The
// refused entries get one warning.
func (p *pProc) apply(vpc VPCKey, entries []*dpv1.Presence) {
	recs := p.recs[vpc]
	next := maps.Clone(recs)
	if next == nil {
		next = map[string]*record{}
	}
	var refused int
	var reason error
	for _, e := range entries {
		rec, gone, err := checkPresence(vpc, e)
		if err != nil {
			if refused++; reason == nil {
				reason = fmt.Errorf("attachment %.64q: %w", e.GetAttachmentId(), err)
			}
			continue
		}
		if gone {
			delete(next, rec.id)
			continue
		}
		next[rec.id] = rec
	}
	if refused > 0 {
		slog.Warn("Refused announcements of a mesh member", "relay", p.ms.name, "tenant", p.tenant, "count", refused, "reason", reason)
	}
	// An empty set stays in the map, so that M gets its VPC.
	if len(next) == 0 {
		delete(p.recs, vpc)
	} else {
		p.recs[vpc] = next
	}
	store(p.up, setKey(keyRecords, vpc), &recordSet{vpc: vpc, recs: next})
}
