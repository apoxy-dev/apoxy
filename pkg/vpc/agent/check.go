// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"cmp"
	"net/netip"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp"
)

// checkTx is the period of the BFD packets of a session in PSP mode. The relay
// has the same period, so the two ends have the same detect time.
const checkTx = bfdl.DefaultTxInterval

// check is the BFD session of a relay session in PSP mode: a child process of
// the session. Its packets go to the PSP socket of the relay in path probes,
// so they use the PSP path.
type check struct {
	mb      *mailbox
	up      *mailbox // The session.
	keys    p2p.ProbeKeys
	bfd     *p2p.Check
	b       *psp.Binding
	seen    netip.AddrPort
	counter uint64
	lost    bool
}

// Messages of a check.
type (
	// checkPkt is a probe packet from the relay.
	checkPkt struct{ pkt []byte }
	// checkSend is a BFD packet for the session to send to the relay.
	checkSend struct {
		c   *check
		pkt []byte
	}
	// checkSeen tells the session that the relay sees a new address of the agent socket.
	checkSeen struct {
		c    *check
		addr netip.AddrPort
	}
	// checkLost tells the session that the PSP path is lost.
	checkLost struct{ c *check }
	// checkEnded is the last message of a check, with its probe counter.
	checkEnded struct {
		c       *check
		counter uint64
	}
)

// newCheck returns the check of a session with its keys, the address of the
// agent socket that the relay sees and the probe counter.
func newCheck(up *mailbox, keys p2p.ProbeKeys, b *psp.Binding, seen netip.AddrPort, counter uint64) *check {
	return &check{mb: newMailbox(), up: up, keys: keys, bfd: p2p.NewCheck(p2p.RoleAgent, checkTx), b: b, seen: seen, counter: counter}
}

// run sends a BFD packet at each period until the session ends the check. The
// packets also keep the NAT mapping, and give the relay a new source address.
func (c *check) run(probes *probeRegistry) {
	t := probes.add(c.keys.SID, func(pkt []byte) { c.mb.send(checkPkt{bytes.Clone(pkt)}) })
	defer func() {
		probes.remove(c.keys.SID, t)
		c.bfd.Close()
		c.up.send(checkEnded{c, c.counter})
	}()
	tx := time.NewTicker(checkTx)
	defer tx.Stop()
	detect := time.NewTicker(checkTx / 2)
	defer detect.Stop()
	c.send()
	for {
		select {
		case <-c.mb.wake:
			for _, m := range c.mb.take() {
				switch m := m.(type) {
				case endMsg:
					return
				case checkPkt:
					c.reply(m.pkt)
				}
			}
		case now := <-detect.C:
			if !c.lost && c.bfd.Lost(now) {
				// This packet tells the relay of the Down state.
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
		c.up.send(checkLost{c})
	}
}

// send gives the session one BFD packet with the state of this end. Its size
// is the largest PSP packet that the agent sends, with the clamp when it is on.
func (c *check) send() {
	c.bfd.SetSize(cmp.Or(c.b.ClampMTU(), c.b.DeviceMTU()) + pspwire.Overhead)
	c.counter++
	pkt := c.bfd.Append(nil, p2p.Probe{SID: c.keys.SID, Counter: c.counter}, &c.keys.Dialer)
	c.up.send(checkSend{c, pkt})
}

// reply takes a BFD packet of the relay.
func (c *check) reply(pkt []byte) {
	if c.lost {
		return
	}
	r, err := p2p.OpenProbe(pkt, &c.keys.Listener)
	if err != nil || !r.Reply || r.BFD == nil {
		return
	}
	if r.Seen != c.seen {
		c.seen = r.Seen
		c.up.send(checkSeen{c, r.Seen})
	}
	changed := c.bfd.Receive(r)
	switch {
	case c.bfd.Lost(time.Now()):
		c.setLost()
	case changed:
		c.send()
	}
}
