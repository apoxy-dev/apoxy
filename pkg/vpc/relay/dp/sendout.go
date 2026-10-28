// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"cmp"
	"net/netip"

	"github.com/apoxy-dev/softpsp/psp"

	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
)

// stepSendOut is send_out of relay.p4, a Go step: the ports entry of m.fwd.port (no_target; it sets
// m.out_meter_index), no trunk to trunk, no local_only to a trunk, and the MTU. Then keys.seal on a
// lane with the outgoing VNI (no_keys), or the FRAME out with m.c.vni (datagram_full), and the out
// cell. It reports true when it drops the packet.
func (x *part) stepSendOut(pkt *packet) bool {
	m := &pkt.m
	o, ok := x.st.port(m.fwd.port)
	if !ok {
		x.drop(pkt, ReasonNoTarget)
		return true
	}
	// After the ports entry of the out port, a drop counts at its meter index.
	m.outMeterIndex = o.MeterIndex
	switch {
	case m.p.trunk == 1 && o.Trunk:
		x.drop(pkt, ReasonTrunkToTrunk)
		return true
	case m.localOnly && o.Trunk:
		x.drop(pkt, ReasonLocalOnly)
		return true
	case o.MTU != 0 && len(pkt.data) > int(o.MTU):
		x.drop(pkt, ReasonMTU)
		return true
	}
	if o.Addr.IsValid() {
		vni := m.c.vni
		if o.Trunk {
			vni = m.p.tag
		}
		if !x.seal(m.fwd.port, o, m.next, vni, m.hash, pkt.data, pkt.mem, cmp.Or(o.MeterIndex, m.p.meterIndex)) {
			return true
		}
	} else {
		w := x.p.writers[m.fwd.port]
		if w == nil {
			x.drop(pkt, ReasonNoTarget)
			return true
		}
		bp := x.p.bufs.Get().(*[]byte)
		err := w(peerconn.EncodeData((*bp)[:0], m.c.vni, pkt.data))
		x.p.bufs.Put(bp)
		if err != nil {
			x.drop(pkt, ReasonDatagramFull)
			return true
		}
	}
	x.countIndex(CounterCells, m.fwd.cell<<1|1, pkt)
	return false
}

// seal seals payload with the Next Header nh and a TX entry of the port session of o on a lane by
// hash, and sends it to the address of that lane. Lane i of 1 to 3 goes to the port address until bit i-1 of seen is set
// (a keepalive from the lane port). payload is in memory mem of the batch. seal writes the PSP
// header into the room of the next packet (the next TX frame of a batch of a worker) and adds a seal
// op; the seal call encrypts later. It counts no_keys when it fails, also in port_drops at the meter
// index mi (0: none). With no room, the packet counts tx_full, and seal reports true, as for a full
// TX ring.
func (x *part) seal(port uint64, o PortAction, nh uint8, vni, hash uint32, payload []byte, mem int, mi uint32) bool {
	tx := x.tx
	sa := x.st.tx[portSession{port, o.Session}].pick(hash)
	n := len(payload) + psp.Overhead
	if sa == nil || n > maxPacket {
		x.p.dropIn(mi, ReasonNoKeys, len(payload))
		return false
	}
	// The offset first: room can move the buf of a batch with no mems.
	src := tx.offset(mem, payload)
	off, ok := tx.room(n)
	if !ok {
		x.p.drop(ReasonTXFull, n)
		return true
	}
	ms := tx.memories()
	if err := sa.put(ms[tx.txMem][off:off+psp.PrefixLen], nh, vni); err != nil {
		x.p.dropIn(mi, ReasonNoKeys, len(payload))
		return false
	}
	tx.seals = append(tx.seals, AEADOp{Key: sa.key, Mem: tx.txMem, Off: off, Len: n, SrcMem: mem, Src: src})
	to := o.Addr
	if sa.lane > 0 && o.Seen&(1<<(sa.lane-1)) != 0 {
		to = laneAddr(o, sa.lane)
	}
	tx.add(to, off, n)
	return true
}

// port returns the port action of the ports entry of id.
func (s *state) port(id uint64) (PortAction, bool) {
	if e := s.ports[id]; e != nil {
		a, ok := e.action.(PortAction)
		return a, ok
	}
	return PortAction{}, false
}

// laneAddr returns the outer address of a lane of the port: lane 0 is its address, and lanes 1 to
// 3 are the 16-bit ports of lanes, from the high bits, at its IP address. A port 0 is its address.
func laneAddr(pa PortAction, lane uint8) netip.AddrPort {
	if lane == 0 {
		return pa.Addr
	}
	port := uint16(pa.Lanes >> (48 - 16*uint(lane)))
	if port == 0 {
		return pa.Addr
	}
	return netip.AddrPortFrom(pa.Addr.Addr(), port)
}
