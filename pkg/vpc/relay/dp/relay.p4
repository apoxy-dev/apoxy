// SPDX-License-Identifier: AGPL-3.0-only

#include <core.p4>
#include <v1model.p4>

// Drop reasons: the index in the drops counter.
const bit<8> R_OLD_SESSION = 1;
const bit<8> R_NO_CONTEXT = 2;
const bit<8> R_SOURCE = 3;
// The Go demux before the pipeline counts its drops at R_DEMUX.
const bit<8> R_DEMUX = 4;
// open_psp: no RX keys entry of the SPI.
const bit<8> R_UNKNOWN_SPI = 5;
// check_in: PSP not from addr, prev or a lane.
const bit<8> R_UNKNOWN_SOURCE = 6;
// check_in: a lane or port meter is red; toRoot: the punt meter is red.
const bit<8> R_METER = 7;
const bit<8> R_NO_ROUTE = 8;
const bit<8> R_NO_TARGET = 9;
const bit<8> R_TRUNK_TO_TRUNK = 10;
const bit<8> R_LOCAL_ONLY = 11;
const bit<8> R_MTU = 12;
// Egress: no TX keys entry of the out port session.
const bit<8> R_NO_KEYS = 13;
// DATAGRAM out: the datagram queue of the datagram writer is full.
const bit<8> R_DATAGRAM_FULL = 14;
// The packet I/O of the interface: no next-hop MAC.
const bit<8> R_NO_NEIGHBOR = 15;
// The root's callback did not take a PacketIn.
const bit<8> R_PUNT_FULL = 16;
// The parser: not a keepalive, a probe, a PSP packet or a data frame, or no IP packet in it.
const bit<8> R_MALFORMED = 17;
// open_psp: the packet did not authenticate, had no sequence number or was a replay.
const bit<8> R_OPEN = 18;
// The packet I/O of the interface: the TX ring of the interface is full.
const bit<8> R_TX_FULL = 19;
// The packet I/O of the interface: the receive queue of the UDP 443 conn is full.
const bit<8> R_QUIC_FULL = 20;
// The handoff of the interface: the channel of the worker of the packet is full.
const bit<8> R_WORKER_FULL = 21;
// The handoff of the interface: the RX queue of the packet has its frame allowance at the workers.
const bit<8> R_WORKER_ALLOWANCE = 22;

// CPU_PORT is the v1model port that connects the control plane (the Go code above the pipeline)
// to the pipeline. A DATAGRAM in comes from it.
const bit<9> CPU_PORT = 255;
// The kind of packet_in for the root.
const bit<8> KIND_PUNT = 1;
const bit<8> KIND_MISS = 2;
// The color of a v1model meter when the packet is over the rate.
const bit<2> METER_RED = 2;
// A keepalive is one byte. A probe has its type and version 2 in its first two bytes, and has
// PROBE_MIN bytes or more. A PSP packet has PSP_MIN bytes or more (the header, the VC and the ICV).
const bit<8> KEEPALIVE = 0x03;
const bit<16> PROBE = 0x0202;
const bit<32> PROBE_MIN = 70;
const bit<32> PSP_MIN = 40;
// PSP Next Header: an inner IPv4 or IPv6 packet, or a message between relays (trunk only).
const bit<8> NEXT_V4 = 4;
const bit<8> NEXT_V6 = 41;
const bit<8> NEXT_MESSAGE = 63;
// The type of a peerconn data frame.
const bit<8> FRAME_DATA = 0x03;

// A VPC name: "<VPC UID>/<network ID>". The CP sends a string; the DP maps it to a number.
@p4runtime_translation("apoxy.dev/relay/name", string)
type bit<32> name_t;
// kind: 1 PUNT, 2 MISS (to the root), 4 DATAGRAM (to the port's datagram writer). hash: the
// QUIC connection. from: the outer address and port of a probe or a keepalive (port 0: the root
// uses the SID).
@controller_header("packet_in")
header packet_in_t {
    bit<8> kind;
    bit<64> port;
    bit<64> session;
    bit<32> hash;
    bit<144> from;
}
// kind: 4 DATAGRAM, 5 SEAL, 6 RAW (SEAL and RAW skip apply; SEAL gets tag 0). to: RAW's outer
// address.
@controller_header("packet_out")
header packet_out_t {
    bit<8> kind;
    bit<64> port;
    bit<64> session;
    bit<144> to;
}

// The PSP header of softpsp, tunnel mode with the VC in clear: Next Header, Hdr Ext Len 2, Crypt
// Offset 2, the S, D, version, V and always-1 bits, the SPI and the IV.
header psp_t {
    bit<8> next;
    bit<8> ext_len;
    bit<2> r;
    bit<6> crypt_off;
    bit<1> s;
    bit<1> d;
    bit<4> version;
    bit<1> v;
    bit<1> one;
    bit<32> spi;
    bit<64> iv;
}
// The VC: the VNI word (the VNI and the flags) and the sequence number.
header vc_t {
    bit<24> vni;
    bit<8> flags;
    bit<32> seq;
}
// A peerconn data frame: its type and the VNI word, then the inner packet.
header frame_t {
    bit<8> kind;
    bit<24> vni;
    bit<8> low;
}
struct headers_t {
    packet_in_t packet_in;
    packet_out_t packet_out;
    psp_t psp;
    vc_t vc;
    frame_t frame;
}
struct port_t {
    bit<1> trunk;
    bit<64> session;
    bit<24> tag;
    bit<144> addr;
    bit<144> prev;
    bit<48> lanes;
    bit<3> seen;
    bit<16> mtu;
    bit<32> meter_index;
}
// The out_ports entry of the out port: what egress needs of its port record.
struct out_port_t {
    bit<1> trunk;
    bit<64> session;
    bit<144> addr;
    bit<48> lanes;
    bit<3> seen;
    bit<16> mtu;
    bit<32> meter_index;
}
struct context_t {
    name_t vpc;
    bit<24> vni;
    bit<32> cell;
}
struct fwd_t {
    bit<64> port;
    bit<32> cell;
}
struct local_t {
    bit<64> port;
    bit<32> cell;
}
struct meta_t {
    bit<64> port;
    bit<64> sa_session;
    bit<32> spi;
    bit<2> lane;
    bit<24> vni;
    bit<24> tag;
    bool local_only;
    bit<128> src;
    bit<128> dst;
    // The target sets from: the outer address and port of a UDP 1000 packet, 0 for a DATAGRAM in.
    bit<144> from;
    // The parser sets punt for a probe or a keepalive.
    bool punt;
    // The PSP Next Header of the inner packet (inner_addrs).
    bit<8> next;
    bit<32> hash;
    // The forward action sets routed.
    bool routed;
    port_t p;
    out_port_t o;
    context_t c;
    fwd_t fwd;
    local_t local;
}

// The inner IPv4 or IPv6 packet after the PSP header or the frame: its source and destination
// address as an IPv6 address (IPv4-mapped for IPv4), and its PSP Next Header, NEXT_V4 or NEXT_V6. It
// gives 0 when the packet is not IPv4 or IPv6.
extern bit<8> inner_addrs(out bit<128> src, out bit<128> dst);
// The flow hash of the inner packet: FNV-1a of the addresses, the protocol and, for TCP, UDP and
// SCTP, the ports. 0 when the packet is not IPv4 or IPv6.
extern bit<32> flow_hash();
// The length of the inner packet: the packet after its parsed headers, which keys.open gave.
extern bit<32> inner_length();
// DATAGRAM out: gives the datagram writer of the port a data frame with vni and the inner packet.
// It gives 0, R_NO_TARGET (the port has no datagram writer) or R_DATAGRAM_FULL.
extern bit<8> datagram_out(in bit<64> port, in bit<24> vni);

// The keys table. Writer: the root, with the agent or trunk key engine. A Read gives an empty key;
// for an RX entry it also gives the packet count and the highest accepted sequence number.
extern PspSa {
    PspSa(bit<32> size);
    // Opens in place by SPI and moves seq. Sets m.port, m.sa_session, m.spi, m.lane (RX keys entry)
    // and m.vni (packet). It does not count the packet. It gives 0, R_UNKNOWN_SPI (no RX entry) or
    // R_OPEN (the version, no sequence number, the AEAD, Next Header or the replay window).
    bit<8> open(in bit<32> spi);
    // Counts a packet in the RX keys entry of spi. check_in calls it after the meters pass, so
    // seq minus packets includes the meter drops (as today's reportRx).
    void count(in bit<32> spi);
    // Seals with the TX keys entry of a lane (flow hash). vni: the outgoing VNI field (trunk port:
    // the sender's tag; access port: m.c.vni).
    bool seal(in bit<64> port, in bit<24> vni);
}

// The counters, the meters and the keys are shared by the ingress and egress controls.
// Cell c: receive at 2c, transmit at 2c+1. The root gives c and the meter indices (pools).
counter(1 << 21, CounterType.packets_and_bytes) cells;
// Drops by reason. The size is 32, so a reason fits the 5 low bits of a port_drops index.
counter(32, CounterType.packets_and_bytes) drops;
// Drops of each port by reason, at (meter index << 5) | reason. An egress drop counts at the out
// port (tx) once its out_ports entry is read, any other drop at the in port (rx). Meter index 0:
// not counted.
counter(1 << 21, CounterType.packets) port_drops;
// Port meter i has lane meters 4i to 4i+3 and punt meter i. Punt meter 0: probes.
meter(1 << 16, MeterType.bytes) port_meter;
meter(1 << 18, MeterType.bytes) lane_meter;
meter(1 << 16, MeterType.packets) punt_meter;
PspSa(1 << 18) keys;

// Ingress. m.port is a relay port (an access or trunk peer), not a v1model port.
control Relay(inout headers_t h,
              inout meta_t m,
              inout standard_metadata_t sm) {
    // hide:begin
    // The drop of a packet: count_drop counts it, in port_drops at the in port, and marks it to
    // drop, then the caller exits. An action calls count_drop and exits itself, because p4test
    // 1.2.5.18 stops with a compiler bug when one action calls an action with exit two times.
    @hidden action count_drop(bit<8> reason) {
        drops.count((bit<32>)reason);
        if (m.p.meter_index != 0) {
            port_drops.count((m.p.meter_index << 5) | (bit<32>)reason);
        }
        mark_to_drop(sm);
    }
    action drop(bit<8> reason) {
        count_drop(reason);
        exit;
    }
    // hide:end
    // A PUNT or a MISS to the root, within the punt meter of the in port (0: a probe or a keepalive).
    // The target gives the root the packet after its parsed headers.
    @hidden action to_root(bit<8> kind) {
        bit<2> color;
        punt_meter.execute_meter(m.p.meter_index, color);
        if (color == METER_RED) {
            count_drop(R_METER);
            exit;
        }
        h.packet_in.setValid();
        h.packet_in.kind = kind;
        h.packet_in.port = m.port;
        h.packet_in.session = m.p.session;
        h.packet_in.hash = m.hash;
        h.packet_in.from = m.from;
        exit;
    }
    // The session of the RX entry or the DATAGRAM in must be the port session. A PSP packet must be
    // from addr, prev or a lane port at the IP of addr, and in its lane meter. Then the port meter,
    // and keys.count for PSP.
    @hidden action check_in() {
        if (m.sa_session != m.p.session) {
            count_drop(R_OLD_SESSION);
            exit;
        }
        bit<2> color;
        if (h.psp.isValid()) {
            bit<16> from_port = (bit<16>)m.from;
            bool lane = m.p.addr != 0 && (m.from >> 16) == (m.p.addr >> 16) && from_port != 0 &&
                (from_port == (bit<16>)(m.p.lanes >> 32) || from_port == (bit<16>)(m.p.lanes >> 16) ||
                 from_port == (bit<16>)m.p.lanes);
            if (m.from == 0 || m.from != m.p.addr && m.from != m.p.prev && !lane) {
                count_drop(R_UNKNOWN_SOURCE);
                exit;
            }
            lane_meter.execute_meter((m.p.meter_index << 2) | (bit<32>)m.lane, color);
            if (color == METER_RED) {
                count_drop(R_METER);
                exit;
            }
        }
        port_meter.execute_meter(m.p.meter_index, color);
        if (color == METER_RED) {
            count_drop(R_METER);
            exit;
        }
        if (h.psp.isValid()) {
            keys.count(m.spi);
        }
    }
    // A trunk packet carries the sender's session tag in the VNI field; tag 0 goes to the root. An
    // access packet has tag 0. Then the inner addresses: a packet that is not IPv4 or IPv6 is
    // malformed.
    @hidden action read_tag() {
        if (m.p.trunk == 1) {
            m.tag = m.vni;
            if (m.tag == 0) {
                to_root(KIND_PUNT);
            }
        }
        m.next = inner_addrs(m.src, m.dst);
        if (m.next == 0) {
            count_drop(R_MALFORMED);
            exit;
        }
    }
    // The out port: the winner, or the local target from a trunk port or with local_only. No entry:
    // MISS from an access port, no_route from a trunk port. No out port: no_route.
    @hidden action route_end() {
        if (!m.routed) {
            if (m.p.trunk == 1) {
                count_drop(R_NO_ROUTE);
                exit;
            }
            to_root(KIND_MISS);
        }
        if (m.p.trunk == 1 || m.local_only) {
            m.fwd.port = m.local.port;
            m.fwd.cell = m.local.cell;
        }
        if (m.fwd.port == 0) {
            count_drop(R_NO_ROUTE);
            exit;
        }
    }
    // Writer: A (access) or M (trunk). addr 0: data on QUIC. lanes: 3 ports at addr's IP. seen:
    // bit i is set after a keepalive from lane i; seal sends lane i to addr until then. prev
    // (access): cleared 5 s after the agent moves. tag: the session tag of an access port.
    action port(bit<1> trunk,
                bit<64> session,
                bit<24> tag,
                bit<144> addr,
                bit<144> prev,
                bit<48> lanes,
                bit<3> seen,
                bit<16> mtu,
                bit<32> meter_index) {
        m.p = {trunk, session, tag, addr, prev, lanes, seen, mtu, meter_index};
    }
    // One classify entry for each access port, or each (trunk port, MS, tag). cell: receive cell.
    action context(name_t vpc, bit<24> vni, bit<32> cell) {
        m.c = {vpc, vni, cell};
    }
    // One entry for each prefix. port, cell: the winner, for a packet from an access port.
    // local_port, local_cell: the best local candidate, from a trunk port or local_only (0: none).
    action forward(bit<64> port, bit<32> cell, bit<64> local_port, bit<32> local_cell) {
        m.fwd = {port, cell};
        m.local = {local_port, local_cell};
        m.routed = true;
    }
    // A source entry of a remote address that V accepted. Egress drops it to a trunk port.
    action local_only() {
        m.local_only = true;
    }
    table ports {
        key = { m.port: exact; }
        actions = { port; drop; }
        const default_action = drop(R_OLD_SESSION);
    }
    // classify, source. Writer: the port's writer. m.p.session in the key: old entries never match.
    table classify {
        key = {
            m.port: exact;
            m.p.session: exact;
            m.tag: exact;
        }
        actions = { context; drop; }
        const default_action = drop(R_NO_CONTEXT);
    }
    // One set: A's attachment prefixes and the remote addresses V accepted, or a tag's records.
    table source {
        key = {
            m.port: exact;
            m.p.session: exact;
            m.tag: exact;
            m.src: lpm;
        }
        actions = { NoAction; local_only; drop; }
        const default_action = drop(R_SOURCE);
    }
    // Writer: V of the VPC.
    table route {
        key = {
            m.c.vpc: exact;
            m.dst: lpm;
        }
        actions = { forward; drop; }
    }
    apply {
        // 1. parse runs the parser and this if up to keys.open. A drop or a punt in this if runs in
        // apply, with all that comes after it, in RX order. A probe or a keepalive goes to the root.
        bit<8> r = 0;
        if (sm.parser_error != error.NoError) {
            drop(R_MALFORMED);
        } else if (m.punt) {
            to_root(KIND_PUNT);
        } else if (h.psp.isValid()) {
            r = keys.open(h.psp.spi);
        }
        if (r != 0) {
            drop(r);
        }
        // 2. A DATAGRAM in starts at ports, with the port and session of its PacketOut.
        ports.apply();
        check_in();
        // 3. The tag and the inner addresses.
        read_tag();
        // 4. On access, the VNI of the packet must be m.c.vni. Count the receive cell. 5. The inner
        // source.
        classify.apply();
        if (m.p.trunk == 0 && m.vni != m.c.vni) {
            drop(R_NO_CONTEXT);
        }
        cells.count(m.c.cell << 1);
        source.apply();
        // 6. Route: from a trunk port or with local_only, the local target. No entry on an access
        // port: MISS. No local target: no_route.
        m.hash = flow_hash();
        route.apply();
        route_end();
        // 7. and 8. are in RelayEgress: the out port and the packet out.
    }
}

// A parser error does not drop the packet: the ingress control gets it with parser_error set.
parser RelayParser(packet_in pkt,
                   out headers_t h,
                   inout meta_t m,
                   inout standard_metadata_t sm) {
    state start {
        transition select(sm.ingress_port) {
            CPU_PORT: datagram_in;
            default: udp;
        }
    }
    // A DATAGRAM in: a PacketOut DATAGRAM from the datagram reader of a port. SEAL and RAW do not
    // come here.
    state datagram_in {
        pkt.extract(h.packet_out);
        pkt.extract(h.frame);
        m.port = h.packet_out.port;
        m.sa_session = h.packet_out.session;
        m.vni = h.frame.vni;
        transition select(h.frame.kind) {
            FRAME_DATA: accept;
        }
    }
    // A UDP 1000 payload: a keepalive, a probe or a PSP packet. Each other packet has no match.
    state udp {
        transition select(sm.packet_length) {
            1: keepalive;
            PSP_MIN .. PROBE_MIN - 1: psp;
            PROBE_MIN .. 0xffffffff: probe;
        }
    }
    state keepalive {
        transition select(pkt.lookahead<bit<8>>()) {
            KEEPALIVE: punt;
        }
    }
    state probe {
        transition select(pkt.lookahead<bit<16>>()) {
            PROBE: punt;
            default: psp;
        }
    }
    state punt {
        m.punt = true;
        transition accept;
    }
    // The checks of psp.ParseTrunkHeader.
    state psp {
        pkt.extract(h.psp);
        pkt.extract(h.vc);
        transition select(h.psp.next) {
            NEXT_V4: psp_ext_len;
            NEXT_V6: psp_ext_len;
            NEXT_MESSAGE: psp_ext_len;
        }
    }
    state psp_ext_len {
        transition select(h.psp.ext_len) {
            2: psp_crypt_off;
        }
    }
    state psp_crypt_off {
        transition select(h.psp.crypt_off) {
            2: psp_d;
        }
    }
    state psp_d {
        transition select(h.psp.d) {
            0: psp_v;
        }
    }
    state psp_v {
        transition select(h.psp.v) {
            1: psp_one;
        }
    }
    state psp_one {
        transition select(h.psp.one) {
            1: psp_version;
        }
    }
    // AES-GCM-128 or AES-GCM-256.
    state psp_version {
        transition select(h.psp.version) {
            0 .. 1: psp_spi;
        }
    }
    // An SPI with its low 31 bits 0 is reserved.
    state psp_spi {
        transition select(h.psp.spi & 0x7fffffff) {
            1 .. 0x7fffffff: accept;
        }
    }
}

control RelayVerify(inout headers_t h,
                    inout meta_t m) {
    apply {
    }
}

// Egress: the out_ports entry of m.fwd.port, the checks of the out port, and the packet out: PSP
// on a lane (keys.seal) or a DATAGRAM to the datagram writer of the port.
control RelayEgress(inout headers_t h,
                    inout meta_t m,
                    inout standard_metadata_t sm) {
    // hide:begin
    // As count_drop of Relay, but a drop counts at the out port once its out_ports entry is read,
    // else at the in port.
    @hidden action count_drop(bit<8> reason) {
        drops.count((bit<32>)reason);
        bit<32> i = m.o.meter_index != 0 ? m.o.meter_index : m.p.meter_index;
        if (i != 0) {
            port_drops.count((i << 5) | (bit<32>)reason);
        }
        mark_to_drop(sm);
    }
    action drop_out(bit<8> reason) {
        count_drop(reason);
        exit;
    }
    // hide:end
    // The port record of the out port: the same writer and the same record as its ports entry.
    action out_port(bit<1> trunk,
                    bit<64> session,
                    bit<144> addr,
                    bit<48> lanes,
                    bit<3> seen,
                    bit<16> mtu,
                    bit<32> meter_index) {
        m.o = {trunk, session, addr, lanes, seen, mtu, meter_index};
    }
    // One entry for each port, written with its ports entry in the same batch.
    table out_ports {
        key = { m.fwd.port: exact; }
        actions = { out_port; drop_out; }
        const default_action = drop_out(R_NO_TARGET);
    }
    apply {
        // A PUNT or a MISS: the target gives the packet to the root after the deparser.
        if (h.packet_in.isValid()) {
            exit;
        }
        // 7. The out_ports entry of m.fwd.port (no_target), no trunk to trunk, no local_only to a
        // trunk, mtu.
        out_ports.apply();
        if (m.p.trunk == 1 && m.o.trunk == 1) {
            drop_out(R_TRUNK_TO_TRUNK);
        }
        if (m.local_only && m.o.trunk == 1) {
            drop_out(R_LOCAL_ONLY);
        }
        if (m.o.mtu != 0 && inner_length() > (bit<32>)m.o.mtu) {
            drop_out(R_MTU);
        }
        // 8. addr set: seal on a lane with the outgoing VNI (a trunk port: the sender's tag); seal
        // counts no_keys itself, with the inner length. addr 0: DATAGRAM out with m.c.vni. Then the
        // transmit cell.
        if (m.o.addr != 0) {
            bit<24> vni = m.o.trunk == 1 ? m.p.tag : m.c.vni;
            if (!keys.seal(m.fwd.port, vni)) {
                mark_to_drop(sm);
                exit;
            }
        } else {
            bit<8> r = datagram_out(m.fwd.port, m.c.vni);
            if (r != 0) {
                drop_out(r);
            }
        }
        cells.count((m.fwd.cell << 1) | 1);
    }
}

control RelayCompute(inout headers_t h,
                     inout meta_t m) {
    apply {
    }
}

// The target gives the root a PacketIn when apply ends with packet_in valid: packet_in is its
// metadata, and the packet after its parsed headers is its payload.
control RelayDeparser(packet_out pkt,
                      in headers_t h) {
    apply {
        pkt.emit(h.packet_in);
    }
}

V1Switch(RelayParser(),
         RelayVerify(),
         Relay(),
         RelayEgress(),
         RelayCompute(),
         RelayDeparser()) main;
