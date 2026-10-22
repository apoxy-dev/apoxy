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
)

// noSource is the source check of the receive SAs of the engine. The data plane checks the sources
// with the source entries, and the engine sees no packet.
func noSource(netip.Addr) bool { return false }

// portKeys is the key state of one access port.
type portKeys struct {
	rx  *keys.Peer
	tx  *keys.TxPeer
	mtu int
	// rxSPIs has the SPIs of the RX entries in the data plane.
	rxSPIs map[uint32]struct{}
	// txSPIs has the SPI of the TX entry of each lane in the data plane, or 0.
	txSPIs [dpLanes]uint32
	// cur is the SPI of the current relay SA and the sequence number at which it is due for a
	// rekey.
	cur     uint32
	rekeyAt uint32
}

// keyEngine is the agent key engine of the root: softpsp, as in the relay before the data plane.
// The data plane holds the SAs. The engine gives the SPIs and the keys and the times of the rekeys.
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

// offer makes the relay SAs of port and applies the SAs of the agent in tx, then writes their keys
// entries. It returns the offer for the agent and the SPIs that the relay refused. With no SA of the
// agent for lane 0 it keeps no keys and returns false, as today.
func (k *keyEngine) offer(ctx context.Context, port uint64, vni uint32, mtu int, tx keys.Request, now time.Time) (keys.Request, []uint32, bool, error) {
	if err := k.close(ctx, port); err != nil {
		return keys.Request{}, nil, false, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	p, err := k.recv.NewPeer(keys.PeerConfig{VNI: vni, MTU: mtu, Lanes: 1, Sources: noSource})
	if err != nil {
		return keys.Request{}, nil, false, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	req, err := p.Offer(now)
	if err != nil {
		p.Revoke()
		return keys.Request{}, nil, false, rpc.Errorf(rpc.Unavailable, "relay SAs: %v", err)
	}
	pk := &portKeys{rx: p, tx: k.send.NewPeer(), mtu: mtu, rxSPIs: map[uint32]struct{}{}}
	refused, err := pk.tx.Apply(tx, now)
	if err != nil || pk.tx.SA(0) == nil {
		pk.rx.Revoke()
		revokeTx(pk.tx)
		if err != nil {
			return keys.Request{}, refused, false, rpc.Errorf(rpc.InvalidArgument, "%v", err)
		}
		return keys.Request{}, refused, false, nil
	}
	var b batch
	if err := k.addRx(&b, port, pk, req.SAs); err == nil {
		err = k.syncTx(&b, port, pk, tx.SAs)
	}
	if err == nil {
		err = b.write(ctx, k.t)
	}
	if err != nil {
		pk.rx.Revoke()
		revokeTx(pk.tx)
		return keys.Request{}, refused, false, rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
	}
	k.ports[port] = pk
	return req, refused, true, nil
}

// apply applies a key change of the agent of port in PSP mode, and writes the TX entries.
func (k *keyEngine) apply(ctx context.Context, port uint64, tx keys.Request, now time.Time) ([]uint32, error) {
	pk := k.ports[port]
	if pk == nil {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "connection has no keys")
	}
	refused, err := pk.tx.Apply(tx, now)
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	var b batch
	err = k.syncTx(&b, port, pk, tx.SAs)
	if err == nil {
		err = b.write(ctx, k.t)
	}
	if err != nil {
		return refused, rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
	}
	return refused, nil
}

// close deletes all keys of port: the relay SAs end at once, as at a revoke.
func (k *keyEngine) close(ctx context.Context, port uint64) error {
	pk := k.ports[port]
	if pk == nil {
		return nil
	}
	delete(k.ports, port)
	pk.rx.Revoke()
	revokeTx(pk.tx)
	var b batch
	for spi := range pk.rxSPIs {
		if err := b.keys(p4.Update_DELETE, &dpv1.PspSaEntry{Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: spi}); err != nil {
			return err
		}
	}
	for _, spi := range pk.txSPIs {
		if spi != 0 {
			if err := b.keys(p4.Update_DELETE, txEntry(port, spi, 0, nil)); err != nil {
				return err
			}
		}
	}
	return b.write(ctx, k.t)
}

// addRx adds the RX entries of the new relay SAs of port to b.
func (k *keyEngine) addRx(b *batch, port uint64, pk *portKeys, sas []keys.SA) error {
	for _, sa := range sas {
		if err := b.keys(p4.Update_INSERT, &dpv1.PspSaEntry{
			Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_RX, Spi: sa.SPI, Key: sa.Key,
			Port: port, Session: accessSession, Lane: uint32(sa.Lane),
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
			if err := b.keys(p4.Update_DELETE, txEntry(port, have, 0, nil)); err != nil {
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
			if err := b.keys(p4.Update_INSERT, txEntry(port, want, lane, key)); err != nil {
				return err
			}
		}
		pk.txSPIs[lane] = want
	}
	return nil
}

func txEntry(port uint64, spi uint32, lane int, key []byte) *dpv1.PspSaEntry {
	return &dpv1.PspSaEntry{
		Direction: dpv1.PspSaDirection_PSP_SA_DIRECTION_TX, Spi: spi, Key: key,
		Port: port, Session: accessSession, Lane: uint32(lane),
	}
}

// rxValue is the receive counts of the relay SAs of one port. It is immutable.
type rxValue struct {
	sas     []*dpv1.SAStats
	packets uint64 // The sum of the packets of sas.
}

// tick runs the rekeys and the expiry of the engine, and makes the keys entries the same. It reads
// the counts of each RX entry: a relay SA rekeys after 3/4 of its packet limit too. It returns the
// rekey of each port and the receive counts of each port.
func (k *keyEngine) tick(ctx context.Context, now time.Time) (map[uint64]keys.Request, map[uint64]*rxValue) {
	ups, err := k.recv.Tick(now)
	if err != nil {
		slog.Warn("Failed to rekey relay SAs", "error", err)
	}
	k.send.Expire(now)
	byPeer := map[*keys.Peer]uint64{}
	for port, pk := range k.ports {
		byPeer[pk.rx] = port
	}
	rekeyed := map[uint64]keys.Request{}
	for _, u := range ups {
		if port, ok := byPeer[u.Peer]; ok {
			rekeyed[port] = keys.Request{Op: keys.OpRekey, SAs: u.SAs}
		}
	}
	rx := map[uint64]*rxValue{}
	err = k.t.Read(ctx, &p4.ReadRequest{Entities: []*p4.Entity{{Entity: &p4.Entity_ExternEntry{ExternEntry: &p4.ExternEntry{
		ExternTypeId: dp.ExternPspSa, ExternId: dp.ExternKeys,
	}}}}}, func(e *p4.Entity) {
		se := &dpv1.PspSaEntry{}
		if e.GetExternEntry().GetEntry().UnmarshalTo(se) != nil || se.GetDirection() != dpv1.PspSaDirection_PSP_SA_DIRECTION_RX {
			return
		}
		pk := k.ports[se.GetPort()]
		if pk == nil {
			return
		}
		v := rx[se.GetPort()]
		if v == nil {
			v = &rxValue{}
			rx[se.GetPort()] = v
		}
		v.sas = append(v.sas, &dpv1.SAStats{Spi: se.GetSpi(), Packets: se.GetPackets(), Seq: se.GetSeq()})
		v.packets += se.GetPackets()
		// The engine sees no packet, so the root rekeys an SA at its packet limit.
		if _, due := rekeyed[se.GetPort()]; !due && se.GetSpi() == pk.cur && se.GetSeq() >= pk.rekeyAt {
			if req, err := pk.rx.Offer(now); err == nil {
				rekeyed[se.GetPort()] = keys.Request{Op: keys.OpRekey, SAs: req.SAs}
			}
		}
	})
	if err != nil {
		slog.Warn("Failed to read keys entries", "error", err)
	}
	for port, pk := range k.ports {
		var b batch
		var err error
		if req, ok := rekeyed[port]; ok {
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
		if err == nil {
			err = b.write(ctx, k.t)
		}
		if err != nil {
			slog.Warn("Failed to write keys entries", "port", port, "error", err)
			delete(rekeyed, port)
		}
	}
	return rekeyed, rx
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
