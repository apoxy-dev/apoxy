// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/keys"
	pspwire "github.com/apoxy-dev/softpsp/psp"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// dpLanes is the number of lanes of a port session in the data plane.
const dpLanes = 4

// keyOp is the op of a keys message from A.
type keyOp uint8

const (
	// opOffer makes the relay SAs of a port and applies the SAs of the agent: the change to PSP
	// mode.
	opOffer keyOp = iota + 1
	// opApply applies a key change of the agent in PSP mode.
	opApply
	// opRevoke deletes all keys of a port, at a PSP path loss.
	opRevoke
	// opClose deletes all keys of a port at its end.
	opClose
	// opRefused gives new relay SAs for the SPIs that a peer relay refused.
	opRefused
)

// noSource is the source check of the receive SAs of the engine. The data plane checks the sources
// with the source entries, and the engine sees no packet.
func noSource(netip.Addr) bool { return false }

// portKeys is the key state of one port session: an access port, or a trunk port with the MS
// number as its session.
type portKeys struct {
	rx      *keys.Peer // Nil on a trunk port before its first offer.
	tx      *keys.TxPeer
	mtu     int
	session uint64
	// rxSPIs has the SPIs of the RX entries in the data plane.
	rxSPIs map[uint32]struct{}
	// txSPIs has the SPI of the TX entry of each lane in the data plane, or 0.
	txSPIs [dpLanes]uint32
	// cur is the SPI of the current relay SA and the sequence number at which it is due for a
	// rekey.
	cur     uint32
	rekeyAt uint32
}

// keyEngine is the key engine of the root for the access and the trunk ports: one softpsp receiver
// and one sender, as in the relay before the data plane, so that the SPIs never clash. Each port
// has its own receive peer and send peer. The data plane holds the SAs. The engine gives the SPIs
// and the keys and the times of the rekeys.
type keyEngine struct {
	t     dp.Target
	table *engine.RxTable
	recv  *keys.Receiver
	send  *keys.Sender
	ports map[uint64]*portKeys
}

func newKeyEngine(t dp.Target) (*keyEngine, error) {
	table, err := engine.NewRxTable(engine.RxConfig{Queues: 1})
	if err != nil {
		return nil, err
	}
	recv, err := keys.NewReceiver(table, pspwire.AESGCM128)
	if err != nil {
		return nil, err
	}
	send, err := keys.NewSender(maxUDP - pspwire.Overhead)
	if err != nil {
		return nil, err
	}
	return &keyEngine{t: t, table: table, recv: recv, send: send, ports: map[uint64]*portKeys{}}, nil
}

// maxUDP is the largest UDP payload of a sealed packet to an agent.
const maxUDP = 1452

// offer makes the relay SAs of port and applies the SAs of the agent in tx. It returns the keys
// entries to write, the offer for the agent, the SPIs that the relay refused, and undo, which takes
// the keys back when their write fails. The deletes of the keys before are in the batch also with an
// error. With no SA of the agent for lane 0 it keeps no keys and returns false, as today.
func (k *keyEngine) offer(port uint64, vni uint32, mtu int, tx keys.Request, now time.Time) (batch, keys.Request, []uint32, bool, func(), error) {
	b, err := k.close(port)
	if err != nil {
		return nil, keys.Request{}, nil, false, nil, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	p, err := k.recv.NewPeer(keys.PeerConfig{VNI: vni, MTU: mtu, Lanes: 1, Sources: noSource})
	if err != nil {
		return b, keys.Request{}, nil, false, nil, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	req, err := p.Offer(now)
	if err != nil {
		p.Revoke()
		return b, keys.Request{}, nil, false, nil, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	pk := &portKeys{rx: p, tx: k.send.NewPeer(), mtu: mtu, session: accessSession, rxSPIs: map[uint32]struct{}{}}
	refused, err := pk.tx.Apply(tx, now)
	if err != nil || pk.tx.SA(0) == nil {
		pk.rx.Revoke()
		revokeTx(pk.tx)
		if err != nil {
			return b, keys.Request{}, refused, false, nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
		}
		return b, keys.Request{}, refused, false, nil, nil
	}
	var nb batch
	if err = k.addRx(&nb, port, pk, req.SAs); err == nil {
		err = k.syncTx(&nb, port, pk, tx.SAs)
	}
	if err != nil {
		pk.rx.Revoke()
		revokeTx(pk.tx)
		return b, keys.Request{}, refused, false, nil, rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
	}
	k.ports[port] = pk
	undo := func() {
		pk.rx.Revoke()
		revokeTx(pk.tx)
		if k.ports[port] == pk {
			delete(k.ports, port)
		}
	}
	return append(b, nb...), req, refused, true, undo, nil
}

// apply applies a key change of the agent of port in PSP mode, and returns the changes of the TX
// entries.
func (k *keyEngine) apply(port uint64, tx keys.Request, now time.Time) (batch, []uint32, error) {
	pk := k.ports[port]
	if pk == nil {
		return nil, nil, rpc.Errorf(rpc.FailedPrecondition, "connection has no keys")
	}
	refused, err := pk.tx.Apply(tx, now)
	if err != nil {
		return nil, nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	var b batch
	if err := k.syncTx(&b, port, pk, tx.SAs); err != nil {
		return nil, refused, rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
	}
	return b, refused, nil
}

// trunkPort returns the keys of a trunk port for the MS session. Keys of an older session go
// first: the batch has the deletes of their entries.
func (k *keyEngine) trunkPort(port, session uint64) (*portKeys, batch, error) {
	if pk := k.ports[port]; pk != nil && pk.session == session {
		return pk, nil, nil
	}
	b, err := k.close(port)
	if err != nil {
		return nil, nil, rpc.Errorf(rpc.Unavailable, "failed to delete keys entries: %v", err)
	}
	pk := &portKeys{tx: k.send.NewPeer(), mtu: trunkMTU, session: session, rxSPIs: map[uint32]struct{}{}}
	k.ports[port] = pk
	return pk, b, nil
}

// trunkOffer makes new relay SAs of a trunk port and returns the changes of their RX entries. The
// SAs of an earlier offer of the session stay for the overlap.
func (k *keyEngine) trunkOffer(port, session uint64, now time.Time) (batch, keys.Request, error) {
	pk, b, err := k.trunkPort(port, session)
	if err != nil {
		return nil, keys.Request{}, err
	}
	if pk.rx == nil {
		// The largest payload sets the packet limit of the SA.
		if pk.rx, err = k.recv.NewPeer(keys.PeerConfig{Trunk: true, MTU: trunkMTU, Lanes: trunkLanes}); err != nil {
			return b, keys.Request{}, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
		}
	}
	req, err := pk.rx.Offer(now)
	if err != nil {
		return b, keys.Request{}, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	if err := k.rxUpdates(&b, port, pk, req.SAs, nil); err != nil {
		return b, keys.Request{}, err
	}
	return b, req, nil
}

// trunkRefused deletes the relay SAs that the peer relay refused, and makes new SAs for their
// lanes.
func (k *keyEngine) trunkRefused(port, session uint64, spis []uint32, now time.Time) (batch, keys.Request, error) {
	pk := k.ports[port]
	if pk == nil || pk.session != session || pk.rx == nil {
		return nil, keys.Request{}, rpc.Errorf(rpc.FailedPrecondition, "trunk has no keys of the session")
	}
	req, err := pk.rx.Refused(spis, now)
	if err != nil {
		return nil, keys.Request{}, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	var b batch
	if err := k.rxUpdates(&b, port, pk, req.SAs, spis); err != nil {
		return nil, keys.Request{}, err
	}
	return b, req, nil
}

// rxUpdates adds to b the RX entries of the new SAs sas of port, and the deletes of the entries of
// the SPIs in gone that the engine deleted. With an error, b is as before.
func (k *keyEngine) rxUpdates(b *batch, port uint64, pk *portKeys, sas []keys.SA, gone []uint32) error {
	var nb batch
	for _, spi := range gone {
		if _, held := pk.rxSPIs[spi]; !held {
			continue
		}
		if _, ok := k.table.Stats(spi); ok {
			continue
		}
		if err := nb.keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spi}); err != nil {
			return rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
		}
		delete(pk.rxSPIs, spi)
	}
	if err := k.addRx(&nb, port, pk, sas); err != nil {
		return rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
	}
	*b = append(*b, nb...)
	return nil
}

// trunkApply applies a key change of the peer relay of a trunk port, and returns the changes of the
// TX entries. It returns the SPIs that the sender holds from another receiver.
func (k *keyEngine) trunkApply(port, session uint64, tx keys.Request, now time.Time) (batch, []uint32, error) {
	pk, b, err := k.trunkPort(port, session)
	if err != nil {
		return nil, nil, err
	}
	refused, err := pk.tx.Apply(tx, now)
	if err != nil {
		return b, nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	var nb batch
	if err := k.syncTx(&nb, port, pk, tx.SAs); err != nil {
		return b, refused, rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
	}
	return append(b, nb...), refused, nil
}

// hasTx reports whether port has a TX SA for lane 0.
func (k *keyEngine) hasTx(port uint64) bool {
	pk := k.ports[port]
	return pk != nil && pk.tx.SA(0) != nil
}

// close deletes all keys of port: the relay SAs end at once, as at a revoke. It returns the deletes
// of their entries.
func (k *keyEngine) close(port uint64) (batch, error) {
	pk := k.ports[port]
	if pk == nil {
		return nil, nil
	}
	delete(k.ports, port)
	if pk.rx != nil {
		pk.rx.Revoke()
	}
	revokeTx(pk.tx)
	var b batch
	for spi := range pk.rxSPIs {
		if err := b.keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spi}); err != nil {
			return nil, err
		}
	}
	for _, spi := range pk.txSPIs {
		if spi != 0 {
			if err := b.keys(p4.Update_DELETE, txEntry(port, pk.session, spi, 0, nil)); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// addRx adds the RX entries of the new relay SAs of port to b.
func (k *keyEngine) addRx(b *batch, port uint64, pk *portKeys, sas []keys.SA) error {
	for _, sa := range sas {
		if err := b.keys(p4.Update_INSERT, &dpv1.PspSaEntry{
			Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: sa.SPI, Key: sa.Key,
			Port: port, Session: pk.session, Lane: uint32(sa.Lane),
		}); err != nil {
			return err
		}
		pk.rxSPIs[sa.SPI] = struct{}{}
		if sa.Lane == 0 {
			limit := pspwire.PacketLimit(pk.mtu)
			pk.cur, pk.rekeyAt = sa.SPI, limit-limit/4
		}
	}
	return nil
}

// syncTx adds to b the changes of the TX entries of port to the SAs that its sender holds now.
// The keys of new SPIs are in sas.
func (k *keyEngine) syncTx(b *batch, port uint64, pk *portKeys, sas []keys.SA) error {
	for lane := range dpLanes {
		var want uint32
		if sa := pk.tx.SA(lane); sa != nil {
			want = sa.SPI()
		}
		have := pk.txSPIs[lane]
		if want == have {
			continue
		}
		if have != 0 {
			if err := b.keys(p4.Update_DELETE, txEntry(port, pk.session, have, 0, nil)); err != nil {
				return err
			}
		}
		if want != 0 {
			var key []byte
			for _, sa := range sas {
				if sa.SPI == want {
					key = sa.Key
				}
			}
			if key == nil {
				return fmt.Errorf("no key for SPI %#x", want)
			}
			if err := b.keys(p4.Update_INSERT, txEntry(port, pk.session, want, lane, key)); err != nil {
				return err
			}
		}
		pk.txSPIs[lane] = want
	}
	return nil
}

func txEntry(port, session uint64, spi uint32, lane int, key []byte) *dpv1.PspSaEntry {
	return &dpv1.PspSaEntry{
		Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spi, Key: key,
		Port: port, Session: session, Lane: uint32(lane),
	}
}

// rxValue is the receive counts of the relay SAs of one port. It is immutable.
type rxValue struct {
	sas     []*dpv1.SAStats
	packets uint64 // The sum of the packets of sas.
}

// readRx returns the RX keys entries of the data plane, with their counts.
func readRx(ctx context.Context, t dp.Target) ([]*dpv1.PspSaEntry, error) {
	var out []*dpv1.PspSaEntry
	err := t.Read(ctx, &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_ExternEntry{ExternEntry: &p4.ExternEntry{
		ExternTypeId: dp.ExternPspSa, ExternId: dp.ExternKeys,
	}}}}}, func(e *p4.Entity) {
		se := &dpv1.PspSaEntry{}
		if e.GetExternEntry().GetEntry().UnmarshalTo(se) == nil && se.GetDirection() == dpv1.PspSaDirection_PSP_SA_DIRECTION_RX {
			out = append(out, se)
		}
	})
	return out, err
}

// keyTick is the result of a tick for one port: the changes of its keys entries, its rekey or nil,
// and expired when its TX SA of lane 0 ended.
type keyTick struct {
	port    uint64
	session uint64
	b       batch
	rekey   *keys.Request
	expired bool
}

// tick runs the rekeys and the expiry of the engine, and returns the changes that make the keys
// entries the same. It reads the counts of each RX entry: a relay SA rekeys after 3/4 of its packet
// limit too. It returns the result of each port with a change, and the receive counts of each port.
// A LoadTarget also gets a sample of the receive rates, for the placement of new sessions.
func (k *keyEngine) tick(ctx context.Context, now time.Time) ([]keyTick, map[uint64]*rxValue) {
	if lt, ok := k.t.(LoadTarget); ok {
		lt.SampleLoad(now)
	}
	entries, err := readRx(ctx, k.t)
	if err != nil {
		slog.Warn("Failed to read keys entries", "error", err)
	}
	ups, err := k.recv.Tick(now)
	if err != nil {
		slog.Warn("Failed to rekey relay SAs", "error", err)
	}
	k.send.Expire(now)
	byPeer := map[*keys.Peer]uint64{}
	for port, pk := range k.ports {
		if pk.rx != nil {
			byPeer[pk.rx] = port
		}
	}
	rekeyed := map[uint64]keys.Request{}
	for _, u := range ups {
		if port, ok := byPeer[u.Peer]; ok {
			rekeyed[port] = keys.Request{Op: keys.OpRekey, SAs: u.SAs}
		}
	}
	rx := map[uint64]*rxValue{}
	for _, se := range entries {
		pk := k.ports[se.GetPort()]
		if pk == nil {
			continue
		}
		v := rx[se.GetPort()]
		if v == nil {
			v = &rxValue{}
			rx[se.GetPort()] = v
		}
		v.sas = append(v.sas, &dpv1.SAStats{Spi: se.GetSpi(), Packets: se.GetPackets(), Seq: se.GetSeq()})
		v.packets += se.GetPackets()
		// The engine sees no packet, so the root rekeys an SA at its packet limit.
		if _, due := rekeyed[se.GetPort()]; !due && pk.rx != nil && se.GetSpi() == pk.cur && se.GetSeq() >= pk.rekeyAt {
			if req, err := pk.rx.Offer(now); err == nil {
				rekeyed[se.GetPort()] = keys.Request{Op: keys.OpRekey, SAs: req.SAs}
			}
		}
	}
	var out []keyTick
	for port, pk := range k.ports {
		var b batch
		var err error
		had := pk.txSPIs[0]
		req, due := rekeyed[port]
		if due {
			err = k.addRx(&b, port, pk, req.SAs)
		}
		// The engine deleted the RX SAs whose time ended, also the old SAs of a rekey.
		for spi := range pk.rxSPIs {
			if _, ok := k.table.Stats(spi); !ok && err == nil {
				err = b.keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spi})
				delete(pk.rxSPIs, spi)
			}
		}
		if err == nil {
			err = k.syncTx(&b, port, pk, nil)
		}
		if err != nil {
			slog.Warn("Failed to write keys entries", "port", port, "error", err)
			continue
		}
		kt := keyTick{port: port, session: pk.session, b: b, expired: had != 0 && pk.txSPIs[0] == 0}
		if due {
			kt.rekey = &req
		}
		if len(b) > 0 || kt.rekey != nil || kt.expired {
			out = append(out, kt)
		}
	}
	return out, rx
}

// revokeTx deletes the SAs of tx, so that the sender can hold their SPIs from another receiver.
func revokeTx(tx *keys.TxPeer) {
	var spis []uint32
	for i := range keys.MaxLanes {
		if sa := tx.SA(i); sa != nil {
			spis = append(spis, sa.SPI())
		}
	}
	_, _ = tx.Apply(keys.Request{Op: keys.OpRevoke, SPIs: spis}, time.Time{})
}
