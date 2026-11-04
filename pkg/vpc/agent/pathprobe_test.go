// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/internal/proc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// ppMTU is the inner MTU of the probe tests.
const ppMTU = 1400

// ppTimes are short discovery timers for the tests.
var ppTimes = discTimes{
	first: 50 * time.Millisecond, run: 600 * time.Millisecond, again: 800 * time.Millisecond,
	backoff: 100 * time.Millisecond, challenge: 400 * time.Millisecond, window: time.Second,
}

// ppSent is one packet that a probe socket sent.
type ppSent struct {
	pkt []byte
	to  netip.AddrPort
}

// ppConn is a loopback UDP socket that keeps each packet that it sends. drop drops them.
type ppConn struct {
	*net.UDPConn
	drop atomic.Bool
	mu   sync.Mutex
	sent []ppSent
}

func (c *ppConn) WriteTo(p []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, ppSent{bytes.Clone(p), udpAddrPort(a)})
	c.mu.Unlock()
	if c.drop.Load() {
		return len(p), nil
	}
	return c.UDPConn.WriteTo(p, a)
}

// sentTo returns the packets sent to to, or to any address when to is not valid.
func (c *ppConn) sentTo(to netip.AddrPort) []ppSent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ppSent
	for _, s := range c.sent {
		if !to.IsValid() || s.to == to {
			out = append(out, s)
		}
	}
	return out
}

func newPPConn(t *testing.T) (*ppConn, netip.AddrPort) {
	t.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = uc.Close() })
	return &ppConn{UDPConn: uc}, uc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// ppEnd is one side of a pair in the probe tests: a socket with the read path of the agent, a
// discovery process and a fake pair that gives the BFD packets to its check.
type ppEnd struct {
	conn  *ppConn
	addr  netip.AddrPort
	reg   probeRegistry
	up    *proc.Mailbox
	role  probeRole
	d     *discovery
	via   *psp.Peer // The direct peer of this side for the other side.
	other *ppEnd
	// wrongSA makes the inner packets of this side come through another SA.
	wrongSA atomic.Bool
	chk     atomic.Pointer[check]

	mu     sync.Mutex
	events []any
	inners []int // The sizes of the inner packets that this side sent.
}

// newPPPair returns two sides with the probe keys of one channel: a is the QUIC client.
func newPPPair(t *testing.T, times discTimes) (a, b *ppEnd) {
	t.Helper()
	var k p2p.ProbeKeys
	_, _ = rand.Read(k.SID[:])
	_, _ = rand.Read(k.Dialer[:])
	_, _ = rand.Read(k.Listener[:])
	a, b = newPPEnd(t, newProbeRole(k, true), times), newPPEnd(t, newProbeRole(k, false), times)
	a.other, b.other = b, a
	return a, b
}

func newPPEnd(t *testing.T, role probeRole, times discTimes) *ppEnd {
	t.Helper()
	conn, addr := newPPConn(t)
	e := &ppEnd{conn: conn, addr: addr, up: proc.NewMailbox(0), role: role, via: new(psp.Peer)}
	e.d = newDiscovery(e.up, role, discIO{sock: conn, inner: e.inner, mtu: func() int { return ppMTU }}, times)
	done := make(chan struct{})
	go e.read()
	go e.pair(done)
	go e.d.run(&e.reg)
	// A probe before the registration of discovery drops, so wait for it.
	require.Eventually(t, func() bool {
		e.reg.mu.Lock()
		defer e.reg.mu.Unlock()
		return e.reg.m[role.sid] != nil
	}, 5*time.Second, time.Millisecond)
	t.Cleanup(func() {
		if c := e.chk.Load(); c != nil {
			c.mb.Send(endMsg{})
		}
		e.d.mb.Send(endMsg{})
		<-done
		_ = conn.Close()
	})
	return e
}

// read is the read path of the agent socket for the probes.
func (e *ppEnd) read() {
	buf := make([]byte, 2048)
	for {
		n, from, err := e.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n > 0 && buf[0] == p2p.TypeProbe {
			e.reg.take(buf[:n], from)
		}
	}
}

// pair is the fake pair: it gives BFD packets to the check, sends the packets of the check to the
// other side and keeps the other messages.
func (e *ppEnd) pair(done chan struct{}) {
	defer close(done)
	for range e.up.Wake() {
		for _, m := range e.up.Take() {
			switch m := m.(type) {
			case discBFD:
				if c := e.chk.Load(); c != nil {
					c.give(m.pkt)
				}
			case checkSend:
				_, _ = e.conn.WriteTo(m.pkt, net.UDPAddrFromAddrPort(e.other.addr))
			default:
				e.mu.Lock()
				e.events = append(e.events, m)
				e.mu.Unlock()
				if _, ok := m.(discEnded); ok {
					return
				}
			}
		}
	}
}

// inner is the fake inner path: it gives the payload to the discovery of the other side, through
// its direct peer, from the address of this side.
func (e *ppEnd) inner(p *psp.Peer, payload []byte, to netip.AddrPort) error {
	if p != e.via {
		return errors.New("unknown direct peer")
	}
	e.mu.Lock()
	e.inners = append(e.inners, len(payload))
	e.mu.Unlock()
	if e.conn.drop.Load() || to != e.other.addr {
		return nil
	}
	via := e.other.via
	if e.wrongSA.Load() {
		via = new(psp.Peer)
	}
	e.other.d.takeInner(payload, via, e.addr)
	return nil
}

func (e *ppEnd) innerSizes() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]int(nil), e.inners...)
}

// find returns the events for which f is true.
func find[T any](e *ppEnd, f func(T) bool) []T {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []T
	for _, m := range e.events {
		if v, ok := m.(T); ok && (f == nil || f(v)) {
			out = append(out, v)
		}
	}
	return out
}

// waitFind waits until an event of type T for which f is true comes, and returns it.
func waitFind[T any](t *testing.T, e *ppEnd, wait time.Duration, f func(T) bool) T {
	t.Helper()
	var got T
	require.Eventually(t, func() bool {
		vs := find(e, f)
		if len(vs) > 0 {
			got = vs[0]
		}
		return len(vs) > 0
	}, wait, 10*time.Millisecond)
	return got
}

// opened returns the probes in sent that open with key.
func opened(sent []ppSent, key *[32]byte) []p2p.Probe {
	var out []p2p.Probe
	for _, s := range sent {
		if p, err := p2p.OpenProbe(s.pkt, key); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// TestPathProbeRound checks a round on real sockets: the candidate that answers passes with
// full-size probes, and the peer learns the source as a peer-reflexive address and checks it.
func TestPathProbeRound(t *testing.T) {
	a, b := newPPPair(t, ppTimes)
	dead := netip.MustParseAddrPort("127.0.0.1:9") // Nothing answers there.
	overlay := netip.MustParseAddrPort("[fd61:706f:7879::1]:4000")
	a.d.mb.Send(discRound{round: 1, addrs: []netip.AddrPort{dead, b.addr, overlay}})

	pass := waitFind(t, a, 2*time.Second, func(m discPassed) bool { return m.addr == b.addr })
	assert.Equal(t, uint32(1), pass.round)
	assert.Positive(t, pass.rtt)
	seen := waitFind[discSeen](t, a, time.Second, nil)
	assert.Equal(t, a.addr, seen.addr)
	ended := waitFind[discRunEnded](t, a, 2*time.Second, nil)
	assert.True(t, ended.passed)
	assert.Len(t, find[discPassed](a, nil), 1, "one pass for each address in a run")

	// b had no round: the source of a is peer-reflexive, and its challenge passes.
	refl := waitFind[discReflexive](t, b, time.Second, nil)
	assert.Equal(t, a.addr, refl.addr)
	waitFind(t, b, 2*time.Second, func(m discPassed) bool { return m.addr == a.addr })
	// The challenge is a probe run of b, which ends at its pass.
	waitFind(t, b, time.Second, func(m discProbing) bool { return m.on })
	waitFind(t, b, time.Second, func(m discProbing) bool { return !m.on })

	full := probeSize(ppMTU)
	assert.Equal(t, ppMTU+pspwire.Overhead, full)
	for _, s := range a.conn.sentTo(netip.AddrPort{}) {
		assert.Len(t, s.pkt, full, "each probe of a is full size")
		assert.NotEqual(t, overlay, s.to, "no probe goes to an overlay address")
	}
	assert.NotEmpty(t, a.conn.sentTo(dead), "the candidate that does not answer gets probes")
	for _, s := range b.conn.sentTo(a.addr) {
		assert.Len(t, s.pkt, full, "no reply is larger than its request")
	}

	// After the challenge time with no timer in b, a new request of a starts a new challenge.
	time.Sleep(ppTimes.run + ppTimes.challenge)
	a.d.mb.Send(discRound{round: 2, addrs: []netip.AddrPort{b.addr}})
	require.Eventually(t, func() bool {
		return len(find(b, func(m discPassed) bool { return m.addr == a.addr })) == 2
	}, 2*time.Second, 10*time.Millisecond)
}

// TestPathProbeDropped checks that a path that drops the probes, or the replies, never passes,
// and that the run of the round ends with no pass.
func TestPathProbeDropped(t *testing.T) {
	cases := []struct {
		name string
		drop func(a, b *ppEnd)
	}{
		{name: "probes", drop: func(a, _ *ppEnd) { a.conn.drop.Store(true) }},
		{name: "replies", drop: func(_, b *ppEnd) { b.conn.drop.Store(true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newPPPair(t, ppTimes)
			tc.drop(a, b)
			a.d.mb.Send(discRound{round: 1, addrs: []netip.AddrPort{b.addr}})
			ended := waitFind[discRunEnded](t, a, 2*time.Second, nil)
			assert.False(t, ended.passed)
			assert.Empty(t, find[discPassed](a, nil))
			// The run sends at once and then after 50, 100, 200 ms in a run of 600 ms.
			assert.Len(t, a.conn.sentTo(b.addr), 4)
		})
	}
}

// ppRaw is a socket that acts as a peer with the keys of a role.
type ppRaw struct {
	conn *net.UDPConn
	addr netip.AddrPort
	role probeRole
}

func newPPRaw(t *testing.T, role probeRole) *ppRaw {
	t.Helper()
	c, addr := newPPConn(t)
	return &ppRaw{conn: c.UDPConn, addr: addr, role: role}
}

// request sends a request with counter c to to and returns it.
func (r *ppRaw) request(t *testing.T, to netip.AddrPort, c uint64, key *[32]byte) []byte {
	t.Helper()
	var id [12]byte
	_, _ = rand.Read(id[:])
	pkt := p2p.AppendProbe(nil, p2p.Probe{SID: r.role.sid, TxID: id, Round: 1, Counter: c}, probeSize(ppMTU), key)
	r.send(t, pkt, to)
	return pkt
}

func (r *ppRaw) send(t *testing.T, pkt []byte, to netip.AddrPort) {
	t.Helper()
	_, err := r.conn.WriteTo(pkt, net.UDPAddrFromAddrPort(to))
	require.NoError(t, err)
}

// read returns the probes with a valid tag that come in wait, and their sizes.
func (r *ppRaw) read(wait time.Duration) (replies, requests []p2p.Probe, sizes []int) {
	buf := make([]byte, 2048)
	_ = r.conn.SetReadDeadline(time.Now().Add(wait))
	for {
		n, _, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		p, err := p2p.OpenProbe(buf[:n], &r.role.rx)
		if err != nil {
			continue
		}
		p.BFD = nil
		if p.Reply {
			replies, sizes = append(replies, p), append(sizes, n)
		} else {
			requests = append(requests, p)
		}
	}
}

// TestPathProbeReplyLimit checks that one source gets at most 10 replies each second.
func TestPathProbeReplyLimit(t *testing.T) {
	_, b := newPPPair(t, ppTimes)
	raw := newPPRaw(t, b.other.role)
	for c := uint64(1); c <= 30; c++ {
		raw.request(t, b.addr, c, &raw.role.tx)
	}
	replies, _, sizes := raw.read(500 * time.Millisecond)
	assert.Len(t, replies, replyRate)
	for i, r := range replies {
		assert.Equal(t, raw.addr, r.Seen)
		assert.Equal(t, probeSize(ppMTU), sizes[i])
	}
	time.Sleep(600 * time.Millisecond)
	for c := uint64(31); c <= 35; c++ {
		raw.request(t, b.addr, c, &raw.role.tx)
	}
	replies, _, _ = raw.read(300 * time.Millisecond)
	assert.Len(t, replies, 5, "one second later the source gets replies again")
}

// TestPathProbeRequestReplay checks that a request seen before, below the counter window, with
// counter 0 or with a bad tag gets no reply and starts no challenge.
func TestPathProbeRequestReplay(t *testing.T) {
	_, b := newPPPair(t, ppTimes)
	raw := newPPRaw(t, b.other.role)
	var bad [32]byte
	steps := []struct {
		name    string
		counter uint64
		replay  bool // Send the first request again.
		bad     bool
		reply   bool
	}{
		{name: "first request", counter: 5, reply: true},
		{name: "the same request again", replay: true},
		{name: "lower counter in the window", counter: 3, reply: true},
		{name: "much higher counter", counter: 100, reply: true},
		{name: "below the window", counter: 30},
		{name: "in the window", counter: 40, reply: true},
		{name: "counter 0", counter: 0},
		{name: "bad tag", counter: 101, bad: true},
	}
	var first []byte
	challenges := 0
	for _, s := range steps {
		key := &raw.role.tx
		if s.bad {
			key = &bad
		}
		if s.replay {
			raw.send(t, first, b.addr)
		} else {
			pkt := raw.request(t, b.addr, s.counter, key)
			if first == nil {
				first = pkt
			}
		}
		replies, reqs, _ := raw.read(150 * time.Millisecond)
		challenges += len(reqs)
		if s.reply {
			assert.Len(t, replies, 1, s.name)
		} else {
			assert.Empty(t, replies, s.name)
		}
	}

	// The first request started a challenge of the raw address. After the challenge time, a
	// replayed request starts none; a new request starts one.
	assert.Positive(t, challenges, "the first request started a challenge")
	_, _, _ = raw.read(ppTimes.run + ppTimes.challenge)
	raw.send(t, first, b.addr)
	replies, reqs, _ := raw.read(400 * time.Millisecond)
	assert.Empty(t, replies)
	assert.Empty(t, reqs, "a replayed request starts no challenge")
	raw.request(t, b.addr, 102, &raw.role.tx)
	_, reqs, _ = raw.read(400 * time.Millisecond)
	assert.NotEmpty(t, reqs, "a new request after the challenge time starts a challenge")
	assert.Len(t, find[discReflexive](b, nil), 1, "the address is peer-reflexive one time")
}

// TestPathProbeReplyChecks checks that a reply counts only when it matches its TxID entry: the
// address, the size, the round, the key, and one time.
func TestPathProbeReplyChecks(t *testing.T) {
	a, _ := newPPPair(t, discTimes{run: 3 * time.Second, first: time.Second})
	raw := newPPRaw(t, a.other.role)
	other := newPPRaw(t, a.other.role)
	a.d.mb.Send(discRound{round: 7, addrs: []netip.AddrPort{raw.addr}})
	_, reqs, _ := raw.read(300 * time.Millisecond)
	require.NotEmpty(t, reqs)
	req := reqs[0]
	reply := func(p p2p.Probe, size int, key *[32]byte) []byte {
		p.Reply, p.Seen = true, a.addr
		return p2p.AppendProbe(nil, p, size, key)
	}
	var bad [32]byte
	wrongRound := req
	wrongRound.Round = 6
	wrongTx := req
	wrongTx.TxID[0] ^= 1
	full := probeSize(ppMTU)
	steps := []struct {
		name string
		pkt  []byte
		from *ppRaw
		pass bool
	}{
		{name: "from another address", pkt: reply(req, full, &raw.role.tx), from: other},
		{name: "another size", pkt: reply(req, full-1, &raw.role.tx), from: raw},
		{name: "another round", pkt: reply(wrongRound, full, &raw.role.tx), from: raw},
		{name: "another TxID", pkt: reply(wrongTx, full, &raw.role.tx), from: raw},
		{name: "bad tag", pkt: reply(req, full, &bad), from: raw},
		{name: "the request itself", pkt: p2p.AppendProbe(nil, req, full, &raw.role.tx), from: raw},
		{name: "valid", pkt: reply(req, full, &raw.role.tx), from: raw, pass: true},
		{name: "the same reply again", pkt: reply(req, full, &raw.role.tx), from: raw},
	}
	for _, s := range steps {
		before := len(find[discPassed](a, nil))
		s.from.send(t, s.pkt, a.addr)
		if s.pass {
			waitFind(t, a, time.Second, func(m discPassed) bool { return m.addr == raw.addr && m.round == 7 })
			continue
		}
		time.Sleep(100 * time.Millisecond)
		assert.Len(t, find[discPassed](a, nil), before, s.name)
	}
}

// TestPathProbeRounds checks the round rules: an older round is ignored, a pair with a direct
// path does not probe a new round, and the again rules.
func TestPathProbeRounds(t *testing.T) {
	t.Run("older round", func(t *testing.T) {
		t.Parallel()
		a, b := newPPPair(t, ppTimes)
		a.d.mb.Send(discRound{round: 2, addrs: []netip.AddrPort{b.addr}})
		waitFind[discRunEnded](t, a, 2*time.Second, nil)
		stale := netip.MustParseAddrPort("127.0.0.1:9")
		a.d.mb.Send(discRound{round: 1, addrs: []netip.AddrPort{stale}})
		a.d.mb.Send(discRound{round: 2, addrs: []netip.AddrPort{stale}})
		time.Sleep(200 * time.Millisecond)
		assert.Empty(t, a.conn.sentTo(stale))
	})
	t.Run("empty round", func(t *testing.T) {
		t.Parallel()
		a, b := newPPPair(t, ppTimes)
		a.conn.drop.Store(true)
		a.d.mb.Send(discRound{round: 1, addrs: []netip.AddrPort{b.addr}})
		waitFind(t, a, time.Second, func(m discProbing) bool { return m.on })
		// A round with no addresses stops the run, and the pair gets its end.
		a.d.mb.Send(discRound{round: 2})
		ended := waitFind(t, a, time.Second, func(m discRunEnded) bool { return m.round == 1 })
		assert.True(t, ended.stopped)
		assert.False(t, ended.passed)
		waitFind(t, a, time.Second, func(m discProbing) bool { return !m.on })
	})
	t.Run("direct path", func(t *testing.T) {
		t.Parallel()
		a, b := newPPPair(t, ppTimes)
		a.d.mb.Send(discDirect{on: true})
		a.d.mb.Send(discRound{round: 1, addrs: []netip.AddrPort{b.addr}})
		time.Sleep(ppTimes.again + 200*time.Millisecond)
		assert.Empty(t, a.conn.sentTo(b.addr))
	})
	t.Run("again with a use, and after a loss", func(t *testing.T) {
		t.Parallel()
		a, b := newPPPair(t, ppTimes)
		a.conn.drop.Store(true)
		a.d.mb.Send(discRound{round: 1, addrs: []netip.AddrPort{b.addr}})
		waitFind[discRunEnded](t, a, 2*time.Second, nil)
		// A use: one more run after the again time, then none with no use in the again time.
		a.d.mb.Send(discUse{})
		require.Eventually(t, func() bool { return len(find[discRunEnded](a, nil)) == 2 }, 3*time.Second, 10*time.Millisecond)
		time.Sleep(ppTimes.again + ppTimes.run)
		assert.Len(t, find[discRunEnded](a, nil), 2, "no run with no use in the again time")
		a.d.mb.Send(discUse{})
		require.Eventually(t, func() bool { return len(find[discRunEnded](a, nil)) == 3 }, 2*time.Second, 10*time.Millisecond)

		// After a loss, with a use all the time: runs after 100 ms, then 200 ms, much sooner than
		// after the again time.
		a.d.mb.Send(discDirect{on: true})
		a.d.mb.Send(discDirect{on: false})
		start := time.Now()
		for len(find[discRunEnded](a, nil)) < 5 && time.Since(start) < 3*time.Second {
			a.d.mb.Send(discUse{})
			time.Sleep(20 * time.Millisecond)
		}
		assert.Len(t, find[discRunEnded](a, nil), 5)
		assert.Less(t, time.Since(start), 2*ppTimes.run+ppTimes.again)
	})
}

// TestPathProbePSPTest checks the PSP test through the direct peer: the inner probe has the size of
// the inner MTU, and a reply through another SA does not count.
func TestPathProbePSPTest(t *testing.T) {
	cases := []struct {
		name    string
		wrongSA bool
		ok      bool
	}{
		{name: "answered through the direct peer", ok: true},
		{name: "reply through another SA", wrongSA: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newPPPair(t, ppTimes)
			b.wrongSA.Store(tc.wrongSA)
			a.d.mb.Send(discTest{peer: a.via, addr: b.addr})
			got := waitFind[discTested](t, a, 2*time.Second, nil)
			assert.Equal(t, tc.ok, got.ok)
			assert.Equal(t, b.addr, got.addr)
			assert.Same(t, a.via, got.peer)
			for _, n := range a.innerSizes() {
				assert.Equal(t, ppMTU-innerHdr, n, "the inner probe has the inner MTU with its IPv6 and UDP header")
			}
			for _, n := range b.innerSizes() {
				assert.Equal(t, ppMTU-innerHdr, n, "the reply has the size of the request")
			}
			assert.NotEmpty(t, b.innerSizes())
			assert.Empty(t, find[discPassed](a, nil), "a PSP test is not an outer probe")
			assert.Empty(t, a.conn.sentTo(netip.AddrPort{}), "a PSP test sends no outer probe")
		})
	}
}

// TestPairCheck checks the BFD check of a direct path in pair mode on real sockets, with a period
// of 100 ms: lost 300 ms after the last packet; the next check continues the counters.
func TestPairCheck(t *testing.T) {
	const tx = 100 * time.Millisecond
	start := func(e *ppEnd, counter, highest uint64) *check {
		c := newPairCheck(e.up, e.role, func() int { return ppMTU }, tx, counter, highest)
		e.chk.Store(c)
		go c.run(nil)
		return c
	}
	up := func(t *testing.T, cs ...*check) {
		t.Helper()
		require.Eventually(t, func() bool {
			for _, c := range cs {
				if !c.bfd.Up() {
					return false
				}
			}
			return true
		}, 2*time.Second, 10*time.Millisecond)
	}
	lost := func(t *testing.T, e *ppEnd, c *check) {
		t.Helper()
		waitFind(t, e, 3*tx+time.Second, func(m checkLost) bool { return m.c == c })
	}
	ended := func(t *testing.T, e *ppEnd, c *check) checkEnded {
		t.Helper()
		c.mb.Send(endMsg{})
		return waitFind(t, e, time.Second, func(m checkEnded) bool { return m.c == c })
	}
	cases := []struct {
		name string
		drop func(a, b *ppEnd)
	}{
		{name: "both ways", drop: func(a, b *ppEnd) { a.conn.drop.Store(true); b.conn.drop.Store(true) }},
		{name: "one way", drop: func(a, _ *ppEnd) { a.conn.drop.Store(true) }},
		{name: "replayed packets only", drop: func(a, b *ppEnd) {
			// a sends none of its new packets; its last BFD packet comes to b again and again.
			sent := a.conn.sentTo(b.addr)
			last := sent[len(sent)-1].pkt
			a.conn.drop.Store(true)
			go func() {
				for range 20 {
					_, _ = a.conn.UDPConn.WriteTo(last, net.UDPAddrFromAddrPort(b.addr))
					time.Sleep(tx / 4)
				}
			}()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := newPPPair(t, ppTimes)
			ca, cb := start(a, 0, 0), start(b, 0, 0)
			up(t, ca, cb)
			time.Sleep(5 * tx)
			assert.Empty(t, find[checkLost](a, nil))
			assert.Empty(t, find[checkLost](b, nil))
			for _, s := range a.conn.sentTo(b.addr) {
				assert.Len(t, s.pkt, probeSize(ppMTU), "a BFD packet has the size of the largest PSP packet")
			}

			dropAt := time.Now()
			tc.drop(a, b)
			lost(t, a, ca)
			lost(t, b, cb)
			assert.Less(t, time.Since(dropAt), 3*tx+time.Second)
			ea, eb := ended(t, a, ca), ended(t, b, cb)
			assert.Positive(t, ea.counter)
			assert.Positive(t, ea.highest)

			// The path returns: checks that continue the counters go up and are lost again.
			a.conn.drop.Store(false)
			b.conn.drop.Store(false)
			ca, cb = start(a, ea.counter, ea.highest), start(b, eb.counter, eb.highest)
			up(t, ca, cb)
			tc.drop(a, b)
			lost(t, a, ca)
			lost(t, b, cb)
		})
	}
	t.Run("one way before both are up", func(t *testing.T) {
		t.Parallel()
		a, b := newPPPair(t, ppTimes)
		a.conn.drop.Store(true)
		startAt := time.Now()
		ca, cb := start(a, 0, 0), start(b, 0, 0)
		// b hears nothing; a hears b until b is lost, then a is lost one detect time later.
		lost(t, b, cb)
		lost(t, a, ca)
		assert.Less(t, time.Since(startAt), 2*3*tx+time.Second)
		assert.False(t, ca.bfd.Up())
	})
	t.Run("a new check from counter 0 is not heard", func(t *testing.T) {
		t.Parallel()
		a, b := newPPPair(t, ppTimes)
		ca, cb := start(a, 0, 0), start(b, 0, 0)
		up(t, ca, cb)
		time.Sleep(15 * tx)
		ended(t, a, ca)
		eb := ended(t, b, cb)
		require.Greater(t, eb.highest, uint64(10))
		// b keeps its highest counter, so the packets of a check of a that starts again from 0 drop.
		_, cb = start(a, 0, 0), start(b, eb.counter, eb.highest)
		lost(t, b, cb)
		assert.False(t, cb.bfd.Up())
	})
}

// TestPairCheckLateDown checks that a replayed BFD packet does not change the state: the first
// packet of a, with the Down state, comes to b again after both are Up.
func TestPairCheckLateDown(t *testing.T) {
	const tx = 100 * time.Millisecond
	a, b := newPPPair(t, ppTimes)
	ca := newPairCheck(a.up, a.role, func() int { return ppMTU }, tx, 0, 0)
	cb := newPairCheck(b.up, b.role, func() int { return ppMTU }, tx, 0, 0)
	a.chk.Store(ca)
	b.chk.Store(cb)
	go ca.run(nil)
	go cb.run(nil)
	require.Eventually(t, func() bool { return ca.bfd.Up() && cb.bfd.Up() }, 2*time.Second, 10*time.Millisecond)
	sent := a.conn.sentTo(b.addr)
	require.NotEmpty(t, sent)
	first := sent[0].pkt
	for range 5 {
		_, err := a.conn.UDPConn.WriteTo(first, net.UDPAddrFromAddrPort(b.addr))
		require.NoError(t, err)
		time.Sleep(tx / 2)
	}
	time.Sleep(4 * tx)
	assert.True(t, cb.bfd.Up())
	assert.Empty(t, find[checkLost](b, nil), "a late Down does not end the path")
	assert.Empty(t, find[checkLost](a, nil))
}
