// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"net/netip"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bfdl"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// checkTx is the period of the BFD packets of a connection in PSP mode.
const checkTx = bfdl.DefaultTxInterval

// Messages of A to its check.
type (
	checkProbe struct{ pr p2p.Probe }
	checkAddr  struct{ addr netip.AddrPort }
)

// checkProc is the process check of A: the relay end of the BFD session of the PSP path. Its
// packets go to the PSP address of A in path probes.
type checkProc struct {
	box  *mailbox
	abox *mailbox
	t    dp.Target
	keys *p2p.ProbeKeys
	bfd  *p2p.Check
	addr netip.AddrPort
}

// startCheck starts a check that sends to addr and tells abox when the path is lost.
func startCheck(t dp.Target, abox *mailbox, keys *p2p.ProbeKeys, addr netip.AddrPort) *checkProc {
	c := &checkProc{box: newMailbox(0), abox: abox, t: t, keys: keys, bfd: p2p.NewCheck(p2p.RoleRelay, checkTx), addr: addr}
	go c.run()
	return c
}

func (c *checkProc) run() {
	t := time.NewTicker(checkTx)
	defer t.Stop()
	defer c.box.close()
	defer c.bfd.Close()
	for {
		select {
		case now := <-t.C:
			if c.bfd.Lost(now) {
				c.lost()
				return
			}
			c.send()
		case <-c.box.sig:
			for _, e := range c.box.take() {
				switch e := e.(type) {
				case checkProbe:
					// The relay pads its packets to the size of the packets of the agent, so that
					// the check tests that size in the two directions.
					c.bfd.SetSize(p2p.MinProbeLen + len(e.pr.BFD))
					changed := c.bfd.Receive(e.pr)
					switch {
					case c.bfd.Lost(time.Now()):
						c.lost()
						return
					case changed:
						// The agent sees the new state at once, not at the next period.
						c.send()
					}
				case checkAddr:
					c.addr = e.addr
				case toEnd:
					return
				}
			}
		}
	}
}

// lost tells the agent that the relay end is Down, and tells A.
func (c *checkProc) lost() {
	c.send()
	c.abox.send(checkLost{c: c})
}

// send sends one BFD packet with the state of the relay end to the PSP address. The agent reads
// its own source address from the packet.
func (c *checkProc) send() {
	if c.addr.IsValid() {
		sendRaw(c.t, c.addr, c.bfd.Append(nil, p2p.Probe{Reply: true, SID: c.keys.SID, Seen: c.addr}, &c.keys.Listener))
	}
}
