// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"net/netip"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/internal/proc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
)

// checkTx is the period of the BFD packets of a session in PSP mode and of a direct path. The
// relay has the same period, so the two ends have the same detect time.
const checkTx = bfdl.DefaultTxInterval

// checkPkts is the most probe packets that wait for a check. A packet goes in
// before its tag check, so a flood with the SID of the check drops here.
const checkPkts = 64

// check is the BFD session of a PSP path, a child process of a relay session in PSP mode or of a
// pair on its direct path (pair mode). Its packets are path probes from the agent socket.
type check struct {
	mb   *proc.Mailbox // From the parent.
	pkts *proc.Mailbox // Probe packets from the socket read path, or from the pair.
	up   *proc.Mailbox // The parent.
	role probeRole
	bfd  *p2p.Check
	mtu  func() int
	tx   time.Duration
	pair bool
	seen netip.AddrPort
	// counter is the last counter sent; highest is the highest counter accepted in pair mode.
	counter, highest uint64
	lost             bool
}

// Messages of a check.
type (
	// checkPkt is a probe packet from the other end.
	checkPkt struct{ pkt []byte }
	// checkSend is a BFD packet for the parent to send to the other end.
	checkSend struct {
		c   *check
		pkt []byte
	}
	// checkSeen tells the session that the relay sees a new address of the agent socket.
	checkSeen struct {
		c    *check
		addr netip.AddrPort
	}
	// checkLost tells the parent that the PSP path is lost.
	checkLost struct{ c *check }
	// checkEnded is the last message of a check, with its counters.
	checkEnded struct {
		c                *check
		counter, highest uint64
	}
)

// newCheck returns the check of a relay session with its keys, the address of the agent socket
// that the relay sees and the probe counter.
func newCheck(up *proc.Mailbox, role probeRole, mtu func() int, seen netip.AddrPort, counter uint64) *check {
	return &check{
		mb: proc.NewMailbox(0), pkts: proc.NewMailbox(checkPkts), up: up,
		role: role, bfd: p2p.NewCheck(p2p.RoleAgent, checkTx), mtu: mtu, tx: checkTx, seen: seen, counter: counter,
	}
}

// newPairCheck returns the check of the direct path of a pair: one packet each tx, lost after 3 tx.
// counter and highest come from the last check of the pair.
func newPairCheck(up *proc.Mailbox, role probeRole, mtu func() int, tx time.Duration, counter, highest uint64) *check {
	return &check{
		mb: proc.NewMailbox(0), pkts: proc.NewMailbox(checkPkts), up: up,
		role: role, bfd: p2p.NewCheck(p2p.RolePeer, tx), mtu: mtu, tx: tx, pair: true,
		counter: counter, highest: highest,
	}
}

// give sends a probe packet of the other end to the check. The pair uses it in pair mode.
func (c *check) give(pkt []byte) { c.pkts.Send(checkPkt{pkt}) }

// run sends a BFD packet at each period until the parent ends the check. A relay check takes the
// probes of its SID from probes; in pair mode probes is nil, and the pair gives the packets.
func (c *check) run(probes *probeRegistry) {
	var t *probeTaker
	if probes != nil {
		t = probes.add(c.role.sid, func(pkt []byte, _ netip.AddrPort) {
			// A full mailbox drops the packet, and BFD takes it as a loss.
			c.pkts.Send(checkPkt{bytes.Clone(pkt)})
		})
	}
	defer func() {
		if t != nil {
			probes.remove(c.role.sid, t)
		}
		c.bfd.Close()
		c.mb.Close()
		c.pkts.Close()
		c.up.Send(checkEnded{c, c.counter, c.highest})
	}()
	tx := time.NewTicker(c.tx)
	defer tx.Stop()
	detect := time.NewTicker(c.tx / 2)
	defer detect.Stop()
	c.send()
	for {
		select {
		case <-c.mb.Wake():
			for _, m := range c.mb.Take() {
				if _, ok := m.(endMsg); ok {
					return
				}
			}
		case <-c.pkts.Wake():
			for _, m := range c.pkts.Take() {
				c.reply(m.(checkPkt).pkt)
			}
		case now := <-detect.C:
			if !c.lost && c.bfd.Lost(now) {
				// This packet tells the other end of the Down state.
				c.send()
				c.setLost()
			}
		case <-tx.C:
			if !c.lost {
				c.send()
			}
		}
	}
}

func (c *check) setLost() {
	if !c.lost {
		c.lost = true
		c.up.Send(checkLost{c})
	}
}

// send gives the parent one BFD packet with the state of this end. Its size is the largest PSP
// packet that the agent sends, with the clamp when it is on.
func (c *check) send() {
	c.bfd.SetSize(probeSize(c.mtu()))
	c.counter++
	pkt := c.bfd.Append(nil, p2p.Probe{SID: c.role.sid, Counter: c.counter}, &c.role.tx)
	c.up.Send(checkSend{c, pkt})
}

// reply takes a BFD packet of the other end. In pair mode only a counter above the highest one
// accepted counts, so a replayed or late packet cannot keep a dead path or end a live one.
func (c *check) reply(pkt []byte) {
	if c.lost {
		return
	}
	r, err := p2p.OpenProbe(pkt, &c.role.rx)
	if err != nil || r.BFD == nil {
		return
	}
	if c.pair {
		if r.Reply || r.Counter <= c.highest {
			return
		}
		c.highest = r.Counter
	} else {
		if !r.Reply {
			return
		}
		if r.Seen != c.seen {
			c.seen = r.Seen
			c.up.Send(checkSeen{c, r.Seen})
		}
	}
	changed := c.bfd.Receive(r)
	switch {
	case c.bfd.Lost(time.Now()):
		if c.pair {
			// The end of a direct path sends one packet with Down at each loss.
			c.send()
		}
		c.setLost()
	case changed:
		c.send()
	}
}
