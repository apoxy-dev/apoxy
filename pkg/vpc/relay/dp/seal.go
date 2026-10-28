// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"cmp"
	"net/netip"

	"github.com/apoxy-dev/softpsp/psp"
)

// Seal is the PspSa method seal: it seals the packet after its parsed headers with a TX entry of
// port and the outgoing VNI vni. no_keys counts at the out port, or at the in port for meter index 0.
func (x *part) Seal(pkt *packet, port uint64, vni uint32) bool {
	return x.seal(port, &pkt.m.o, pkt.m.next, vni, pkt.m.hash, pkt.data, pkt.mem, cmp.Or(pkt.m.o.meterIndex, pkt.m.p.meterIndex))
}

// seal seals payload with the Next Header nh and a TX entry of the port session of o on a lane by
// hash, and sends it to the address of that lane. Lane i of 1 to 3 goes to the port address until bit i-1 of seen is set
// (a keepalive from the lane port). payload is in memory mem of the batch. seal writes the PSP
// header into the room of the next packet (the next TX frame of a batch of a worker) and adds a seal
// op; the seal call encrypts later. It counts no_keys when it fails, also in port_drops at the meter
// index mi (0: none). With no room, the packet counts tx_full, and seal reports true, as for a full
// TX ring.
func (x *part) seal(port uint64, o *outPortT, nh uint8, vni, hash uint32, payload []byte, mem int, mi uint32) bool {
	tx := x.tx
	sa := x.st.tx[portSession{port, o.session}].pick(hash)
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
	to := o.addr
	if sa.lane > 0 && o.seen&(1<<(sa.lane-1)) != 0 {
		to = laneAddr(o.addr, o.lanes, sa.lane)
	}
	tx.add(to, off, n)
	return true
}

// laneAddr returns the outer address of a lane of a port with the address addr: lane 0 is addr,
// and lanes 1 to 3 are the 16-bit ports of lanes, from the high bits, at the IP of addr. A port 0
// is addr.
func laneAddr(addr netip.AddrPort, lanes uint64, lane uint8) netip.AddrPort {
	if lane == 0 {
		return addr
	}
	port := uint16(lanes >> (48 - 16*uint(lane)))
	if port == 0 {
		return addr
	}
	return netip.AddrPortFrom(addr.Addr(), port)
}
