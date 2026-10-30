// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"crypto/x509"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// The keys of the values in the watchable maps.
const (
	keyRoutes  = "routes"  // *routeTable, V to A.
	keyNetwork = "network" // *Network, root to V and V to A.
	keyTrust   = "trust"   // *trustGen, root to V and V to A.
	keyRx      = "rx"      // *rxValue, V to A. The root stores rxKey(port) in the map of V.
	keyState   = "state"   // *stateValue, A to V.
	// keyAnnounce is the key of the announcement set of V in its up map: *annSet, V to root.
	keyAnnounce = "announce"
)

// rxKey is the key of the receive counts of a port in the map of V.
func rxKey(port uint64) string { return keyRx + "/" + strconv.FormatUint(port, 10) }

// stateValue is the announcer state that A gives its candidates, and why it changed.
type stateValue struct {
	state  dpv1.AnnouncerState
	reason string
}

// link is one authenticated QUIC connection of an agent. The handlers of its calls find their
// process through it.
type link struct {
	qc       *quic.Conn
	vpc      VPCKey
	subject  string
	chain    []*x509.Certificate // Agent cert chain, leaf first.
	verified time.Time           // Time of the cert check of the handshake.
	probe    p2p.ProbeKeys

	// session is true after the first Session call.
	session atomic.Bool
	// a is the mailbox of the A of the connection, set before the root answers the Session call.
	a atomic.Pointer[mailbox]
	// owned is true after the root took the connection: finished then closes.
	owned    atomic.Bool
	finished chan struct{} // Closed when the process of the connection and its hook tasks ended.
	finish   sync.Once
	// streamDone is closed when the process of the connection stops its use of the Session stream.
	streamDone chan struct{}
	streamOnce sync.Once
}

func (l *link) done() { l.finish.Do(func() { close(l.finished) }) }

func (l *link) streamEnd() { l.streamOnce.Do(func() { close(l.streamDone) }) }

// close closes the QUIC connection with code and msg.
func (l *link) close(code dpv1.RelayCloseCode, msg string) {
	_ = l.qc.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// remote returns the address of the agent end of the QUIC connection now.
func (l *link) remote() netip.AddrPort { return addrPort(l.qc.RemoteAddr()) }

// Events of the root.
type (
	// accepted is a Session call with a valid Hello. res gets nil when a process took the call.
	accepted struct {
		l     *link
		st    sessionStream
		hello *dpv1.Hello
		res   chan error
	}
	desiredChanged struct{ key any }
	recheckEv      struct{ project string }
	// slotLost is the end of the lease of the addresses of an attachment. done closes after the
	// ports entry of its connection is gone.
	slotLost struct {
		port uint64
		att  string
		done chan struct{}
	}
	drainEv  struct{}
	endAllEv struct {
		code dpv1.RelayCloseCode
		msg  string
	}
	statsAsk struct{ reply chan []AttachmentStats }
	packetIn struct {
		md      pinMeta
		payload []byte
	}
	hookDone     struct{}
	hookPortDone struct{ port uint64 }
	// assignDone is the result of an Assign hook task.
	assignDone struct {
		port  uint64
		att   *Attachment
		addrs []netip.Prefix
		err   error
	}
	// fromV is a message of a V to the root.
	fromV struct {
		v   *vChild
		msg any
	}
)

// pinMeta is the metadata of a PacketIn.
type pinMeta struct {
	kind    uint8
	port    uint64
	session uint64
	from    netip.AddrPort
}

// Messages of V and A to the root. A sends them to V, and V sends them on.
type (
	vAssign struct {
		port uint64
		att  *Attachment
	}
	// vKeys asks for a key operation for the port of an A. chain is set for the operation of a
	// call: the root writes its keys entries at once.
	vKeys struct {
		port  uint64
		op    keyOp
		req   keys.Request
		vni   uint32
		mtu   int
		chain bool
	}
	vAttachmentStart struct {
		port uint64
		att  *Attachment
	}
	// vAttachmentEnd is the end of an attachment, with its final counts. A nil stats is a failed
	// attach: only its Release runs.
	vAttachmentEnd struct {
		port  uint64
		att   *Attachment
		cell  uint32
		stats *AttachmentStats
	}
	vConnEnded struct {
		port uint64
		ends []vAttachmentEnd
	}
	// vLanes gives the root the lane ports in the ports entry of the A of port. Bit i of seen is
	// set after a keepalive from lanes[i].
	vLanes struct {
		port  uint64
		lanes [MaxLaneSources]netip.AddrPort
		seen  uint8
	}
	vStatsAnswer struct {
		ask   uint64
		stats []AttachmentStats
	}
	vEnded struct{}
	// vTables has the table changes of one event of the A of port, or of V for port 0. The root
	// answers it with toTablesDone after its write. chain is set when a waiting chain needs the
	// event: the root writes the pending batch at once.
	vTables struct {
		port  uint64
		b     batch
		chain bool
	}
)

// Messages down the tree, from the root to V and from V to A.
type (
	// toConn starts the A of a new main connection with the mailbox box.
	toConn struct {
		l     *link
		st    sessionStream
		hello *dpv1.Hello
		box   *mailbox
		port  uint64
		tag   uint32
		cell  uint32
		meter uint32
	}
	toAssigned struct {
		port     uint64
		att      string
		addrs    []netip.Prefix
		cell     uint32
		instance uint64
		err      error
	}
	toKeysDone struct {
		port    uint64
		op      keyOp
		offer   keys.Request
		refused []uint32
		ok      bool
		// tx is true when a trunk port has a TX SA for lane 0 after the operation.
		tx  bool
		err error
	}
	// toRekeyed gives a rekey of the port keys of session. M takes only a rekey of its MS now.
	toRekeyed struct {
		port    uint64
		session uint64
		req     keys.Request
	}
	// toTablesDone answers a tables event after its write: of the A of port, or of V or M for
	// port 0.
	toTablesDone struct {
		port uint64
		err  error
	}
	toPacketIn struct {
		port uint64
		pin  packetIn
	}
	toStats    struct{ ask uint64 }
	toSlotLost struct {
		port uint64
		done chan struct{}
	}
	toDrain   struct{ alternates []*dpv1.RelayRef }
	toEndConn struct {
		code dpv1.RelayCloseCode
		msg  string
	}
	toEnd struct{}
	// valuesChanged tells a process that the values of keys in its down map changed.
	valuesChanged struct{ keys []string }
)

// Messages of A to V, and the answers of V.
type (
	aAttach struct {
		port uint64
		att  *Attachment
		cell uint32
	}
	aDetach struct {
		port uint64
		id   string
	}
	aEnded struct {
		port uint64
		ends []vAttachmentEnd
	}
	aStatsAnswer struct {
		port  uint64
		ask   uint64
		stats []AttachmentStats
	}
	// aStateChanged tells V that the up map of the A of port changed.
	aStateChanged struct{ port uint64 }

	attached struct {
		id  string
		err error
	}
	detached struct{ id string }
)

// callKind is the kind of a call of the agent to A.
type callKind uint8

const (
	callAttach callKind = iota + 1
	callDetach
	callRekey
	callLanes
)

// aCall is a unary call of the agent. A answers it on res.
type aCall struct {
	kind callKind
	in   proto.Message
	res  chan callResult
}

type callResult struct {
	out proto.Message
	err error
}

// pinOf decodes a PacketIn of the data plane.
func pinOf(p *p4.PacketIn) (packetIn, bool) {
	md, err := dp.DecodePacketInMeta(p.GetMetadata())
	if err != nil {
		return packetIn{}, false
	}
	return packetIn{md: pinMeta{kind: md.Kind, port: md.Port, session: md.Session, from: md.From}, payload: p.GetPayload()}, true
}
