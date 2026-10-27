// SPDX-License-Identifier: AGPL-3.0-only

package relay_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/p2p"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	project = "project-a"
	vpcUID  = "vpc-a"
	netID   = 0x1234
	relayID = "relay-1"
	// wait is the longest time that a test waits for one result of the relay.
	wait = 10 * time.Second
)

var (
	vpcKey = relay.VPCKey{Project: project, UID: vpcUID}
	vpcRef = &dpv1.VPCRef{ProjectId: project, VpcUid: vpcUID}
)

// addresses gives each attachment the next /96 of its slot of the VPC network, and keeps the
// hooks that the relay called.
type addresses struct {
	mu       sync.Mutex
	slot     int
	next     int
	lost     map[string]func()
	attached []string
	released []string
	// holdNext makes the next Assign wait for the end of its ctx. held gets a value when it waits.
	holdNext bool
	held     chan struct{}
}

func (a *addresses) Assign(ctx context.Context, att *relay.Attachment, onLost func()) ([]netip.Prefix, error) {
	a.mu.Lock()
	if a.holdNext {
		a.holdNext = false
		a.mu.Unlock()
		a.held <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	defer a.mu.Unlock()
	a.next++
	if a.lost == nil {
		a.lost = map[string]func(){}
	}
	a.lost[att.ID] = onLost
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd61:706f:7879:12:3400:%x::/96", a.slot<<8+a.next))}, nil
}

func (a *addresses) Attached(att *relay.Attachment) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attached = append(a.attached, att.ID)
}

func (a *addresses) Release(att *relay.Attachment) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.released = append(a.released, att.ID)
}

// holdOne makes the next Assign wait until its connection closes. The channel gets a value when
// it waits.
func (a *addresses) holdOne() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.holdNext, a.held = true, make(chan struct{}, 1)
	return a.held
}

// loseSlot ends the lease of the addresses of attachment id, as the host does.
func (a *addresses) loseSlot(id string) {
	a.mu.Lock()
	f := a.lost[id]
	a.mu.Unlock()
	f()
}

func (a *addresses) isAttached(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Contains(a.attached, id)
}

func (a *addresses) isReleased(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Contains(a.released, id)
}

func (a *addresses) releases() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.released)
}

// trust trusts one agent CA and has a revocation list. A set err makes each call fail.
type trust struct {
	mu      sync.Mutex
	pool    *x509.CertPool
	revoked []vpcv1alpha1.RevokedAgent
	err     error
}

func (t *trust) AgentCA(string) (*x509.CertPool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pool, t.err
}

func (t *trust) Revoked(string, string) ([]vpcv1alpha1.RevokedAgent, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.revoked), t.err
}

func (t *trust) revoke(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.revoked = append(t.revoked, vpcv1alpha1.RevokedAgent{Name: name, RevokedAt: metav1.NewTime(time.Now())})
}

func (t *trust) setErr(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.err = err
}

// env is a relay on a loopback data plane with the Relay service on real QUIC.
type env struct {
	id    string
	ca    *vpctest.CA
	r     *relay.Router
	srv   *relay.Server
	addrs *addresses
	trust *trust
	quic  *net.UDPAddr
	data  *net.UDPAddr
	ends  chan relay.AttachmentStats
	// changes and sessions get the mesh changes and the mesh sessions of the relay.
	changes  chan relay.MeshChange
	sessions chan *relay.MeshSession
	// stop stops the relay: its root ends, then its listener.
	stop func()
}

// envOpts are the options of a test relay.
type envOpts struct {
	id   string // Relay ID, and the name in the mesh. Empty is relayID.
	ca   *vpctest.CA
	slot int    // The slot of the addresses that the relay gives.
	mtu  uint32 // The MTU of the VPC network. Zero is the default MTU.
	// mesh makes the relay a mesh member, with its name id and the certificates of ca.
	mesh     bool
	snapshot func() []byte
	// dataSend wraps the data socket for the packets that the data plane sends.
	dataSend func(net.PacketConn) net.PacketConn
	// quicSend wraps the QUIC socket of the agent connections and the mesh sessions.
	quicSend func(net.PacketConn) net.PacketConn
	// interval is the table write interval of the relay. nil is the default.
	interval *time.Duration
	// writes, when set, is the data plane target of the relay: it keeps each Write.
	writes *writeLog
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, envOpts{})
}

func newEnvWith(t testing.TB, o envOpts) *env {
	t.Helper()
	if o.id == "" {
		o.id = relayID
	}
	ca := o.ca
	if ca == nil {
		var err error
		ca, err = vpctest.NewCA()
		require.NoError(t, err)
	}
	lo, err := vpctest.NewLoopback()
	require.NoError(t, err)
	if o.dataSend != nil {
		lo.Target = vpctest.NewSocketTarget(o.dataSend(lo.Data))
	}
	go func() { _ = lo.Run() }()
	e := &env{
		id:       o.id,
		ca:       ca,
		addrs:    &addresses{slot: o.slot},
		trust:    &trust{pool: ca.Pool()},
		quic:     lo.QUIC.LocalAddr().(*net.UDPAddr),
		data:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(lo.DataPort())},
		ends:     make(chan relay.AttachmentStats, 64),
		changes:  make(chan relay.MeshChange, 64),
		sessions: make(chan *relay.MeshSession, 64),
	}
	var target relay.PortTarget = lo.Target
	if o.writes != nil {
		o.writes.SocketTarget = lo.Target
		target = o.writes
	}
	e.r, err = relay.NewRouter(relay.Config{
		Relay:              &dpv1.RelayRef{Id: o.id, Addresses: []string{fmt.Sprintf("192.0.2.%d", 1+o.slot)}},
		Trust:              e.trust,
		Addresses:          e.addrs,
		Target:             target,
		LaneSources:        3,
		TableWriteInterval: o.interval,
	})
	require.NoError(t, err)
	e.r.OnAttachmentEnd(func(s relay.AttachmentStats) { e.ends <- s })
	e.r.AddTenant(project)
	e.r.AddVPC(vpcKey, relay.Network{ID: netID, Name: "net-a", MTU: o.mtu})
	cert, err := ca.RelayCert(o.id)
	require.NoError(t, err)
	var qconn net.PacketConn = lo.QUIC
	if o.quicSend != nil {
		qconn = o.quicSend(lo.QUIC)
	}
	tr := &quic.Transport{Conn: qconn}
	if o.mesh {
		require.NoError(t, e.r.SetMesh(o.id, relay.MeshConfig{
			TLS:      &tls.Config{Certificates: []tls.Certificate{*cert}, InsecureSkipVerify: true},
			Verify:   verifyRelay(ca),
			Snapshot: o.snapshot,
		}, tr, &quic.Config{EnableDatagrams: true}))
		e.r.OnMeshChange(func(c relay.MeshChange) { e.changes <- c })
		e.r.OnMeshSession(func(s *relay.MeshSession) { e.sessions <- s })
	}
	runCtx, stopRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = e.r.Run(runCtx)
	}()

	ln, err := tr.Listen(e.r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}),
		e.r.ListenConfig(&quic.Config{EnableDatagrams: true, KeepAlivePeriod: relay.AgentKeepAlive}))
	require.NoError(t, err)
	e.srv = &relay.Server{R: e.r}
	serveCtx, stopServe := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = e.srv.Serve(serveCtx, ln)
	}()
	var once sync.Once
	e.stop = func() {
		once.Do(func() {
			stopRun()
			<-runDone
			_ = ln.Close()
			stopServe()
			<-serveDone
			_ = tr.Close()
			_ = lo.Close()
		})
	}
	t.Cleanup(e.stop)
	return e
}

// verifyRelay accepts a relay certificate of ca that names the relay.
func verifyRelay(ca *vpctest.CA) relay.MeshVerify {
	return func(chain []*x509.Certificate, name string, _ netip.AddrPort) error {
		if len(chain) == 0 {
			return errors.New("no certificate")
		}
		_, err := chain[0].Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		return err
	}
}

// agent is the agent end of one QUIC connection to the relay.
type agent struct {
	t    testing.TB
	name string
	qc   *quic.Conn
	rc   dpv1.RelayClient
	keys p2p.ProbeKeys
	st   rpc.BidiStreamClient[dpv1.SessionRequest, dpv1.SessionResponse]

	mu      sync.Mutex
	msgs    []*dpv1.SessionResponse
	at      []time.Time // The arrival time of each message of msgs.
	routes  map[string]*dpv1.Route
	recvErr error

	// PSP state of the agent.
	probes uint64
	seq    uint32
	rxSPI  uint32 // The agent SA, which the relay sends with.
	rxKey  []byte
	txSPI  uint32 // The relay SA, which the agent sends with.
	txKey  []byte
}

// dial opens a connection with a new cert of agent name in the VPC of the env.
func (e *env) dial(t testing.TB, name string) *agent {
	t.Helper()
	a, err := e.dialVPC(t, vpcUID, name)
	require.NoError(t, err)
	return a
}

func (e *env) dialVPC(t testing.TB, vpc, name string) (*agent, error) {
	t.Helper()
	cred, err := e.ca.Credential(project, vpc, name, time.Hour)
	require.NoError(t, err)
	return e.dialCred(t, name, cred)
}

func (e *env) dialCred(t testing.TB, name string, cred *identity.Credential) (*agent, error) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udp}
	t.Cleanup(func() {
		_ = tr.Close()
		_ = udp.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	qc, err := tr.Dial(ctx, e.quic, &tls.Config{
		Certificates:       []tls.Certificate{*cred.TLSCertificate()},
		NextProtos:         []string{dpv1.ALPNRelay},
		InsecureSkipVerify: true,
	}, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: time.Second})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	keys, err := p2p.NewProbeKeys(qc.ConnectionState().TLS)
	require.NoError(t, err)
	return &agent{t: t, name: name, qc: qc, rc: dpv1.NewRelayClient(rpc.NewConn(qc, nil)), keys: keys, routes: map[string]*dpv1.Route{}}, nil
}

func hello(mode dpv1.Mode) *dpv1.Hello {
	return &dpv1.Hello{Mode: mode, Version: dpv1.LocalVersion("test"), Name: "agent"}
}

// session runs the Session call with h and returns the first message of the relay. Then a task
// keeps the next messages.
func (a *agent) session(h *dpv1.Hello) (*dpv1.SessionResponse, error) {
	f := <-a.begin(h)
	return f.m, f.err
}

// first is the first message of the relay on a Session call, or its error, and its arrival time.
type first struct {
	m   *dpv1.SessionResponse
	err error
	at  time.Time
}

// begin sends h on a new Session call. The channel gets the first message of the relay. Then a
// task keeps the next messages.
func (a *agent) begin(h *dpv1.Hello) <-chan first {
	ctx, cancel := context.WithCancel(context.Background())
	a.t.Cleanup(cancel)
	st, err := a.rc.Session(ctx)
	require.NoError(a.t, err)
	require.NoError(a.t, st.Send(&dpv1.SessionRequest{Msg: &dpv1.SessionRequest_Hello{Hello: h}}))
	out := make(chan first, 1)
	go func() {
		m, err := st.Recv()
		if err != nil {
			out <- first{err: err, at: time.Now()}
			return
		}
		a.st = st
		out <- first{m: m, at: time.Now()}
		for {
			m, err := st.Recv()
			now := time.Now()
			a.mu.Lock()
			if err != nil {
				a.recvErr = err
				a.mu.Unlock()
				return
			}
			a.msgs = append(a.msgs, m)
			a.at = append(a.at, now)
			if d := m.GetRouteDelta(); d != nil {
				for _, r := range d.GetRemove() {
					delete(a.routes, r.GetPrefix())
				}
				for _, r := range d.GetAdd() {
					a.routes[r.GetPrefix()] = r
				}
			}
			a.mu.Unlock()
		}
	}()
	return out
}

// open runs the Session call in mode and returns Welcome.
func (a *agent) open(mode dpv1.Mode) *dpv1.Welcome {
	a.t.Helper()
	m, err := a.session(hello(mode))
	require.NoError(a.t, err)
	require.NotNil(a.t, m.GetWelcome(), "first message: %v", m)
	return m.GetWelcome()
}

// attach attaches the agent with routes and returns the answer.
func (a *agent) attach(routes ...string) *dpv1.AttachResponse {
	a.t.Helper()
	res, err := a.rc.Attach(context.Background(), &dpv1.AttachRequest{Vpc: vpcRef, Name: a.name, Routes: routes})
	require.NoError(a.t, err)
	return res
}

// detach detaches attachment id of the agent. The answer comes after the relay deleted its
// entries.
func (a *agent) detach(id string) {
	a.t.Helper()
	_, err := a.rc.Detach(context.Background(), &dpv1.DetachRequest{AttachmentId: id})
	require.NoError(a.t, err)
}

// addr returns the overlay address of an attachment.
func addr(t testing.TB, res *dpv1.AttachResponse) netip.Addr {
	t.Helper()
	require.NotEmpty(t, res.GetAddresses())
	return relay.OverlayAddr(netip.MustParsePrefix(res.GetAddresses()[0]))
}

// all returns the messages of the relay that match f.
func (a *agent) all(f func(*dpv1.SessionResponse) bool) []*dpv1.SessionResponse {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*dpv1.SessionResponse
	for _, m := range a.msgs {
		if f(m) {
			out = append(out, m)
		}
	}
	return out
}

// waitMsg waits for n messages that match f and returns the last one.
func (a *agent) waitMsg(n int, f func(*dpv1.SessionResponse) bool) *dpv1.SessionResponse {
	a.t.Helper()
	var got []*dpv1.SessionResponse
	require.Eventually(a.t, func() bool {
		got = a.all(f)
		return len(got) >= n
	}, wait, 10*time.Millisecond)
	return got[len(got)-1]
}

func (a *agent) route(prefix string) *dpv1.Route {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.routes[prefix]
}

// waitRoute waits until the route table of the agent has prefix, or not.
func (a *agent) waitRoute(prefix string, want bool) *dpv1.Route {
	a.t.Helper()
	require.Eventually(a.t, func() bool { return (a.route(prefix) != nil) == want }, wait, 10*time.Millisecond, prefix)
	return a.route(prefix)
}

// closed waits for the end of the connection and returns the close code and message of the relay.
func (a *agent) closed() (dpv1.RelayCloseCode, string) {
	a.t.Helper()
	select {
	case <-a.qc.Context().Done():
	case <-time.After(wait):
		a.t.Fatal("connection did not close")
	}
	var ae *quic.ApplicationError
	require.ErrorAs(a.t, context.Cause(a.qc.Context()), &ae)
	return dpv1.RelayCloseCode(ae.ErrorCode), ae.ErrorMessage
}

// open reports whether the connection is open after d.
func (a *agent) openAfter(d time.Duration) bool {
	select {
	case <-a.qc.Context().Done():
		return false
	case <-time.After(d):
		return true
	}
}

// packet returns an IPv6 packet of n bytes from src to dst.
func packet(src, dst netip.Addr, n int) []byte {
	b := make([]byte, n)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(n-40))
	b[6], b[7] = 17, 64
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	_, _ = rand.Read(b[40:])
	return b
}

// sendFrame sends inner in a data frame on the connection.
func (a *agent) sendFrame(inner []byte) {
	a.t.Helper()
	require.NoError(a.t, a.qc.SendDatagram(peerconn.EncodeData(nil, netID, inner)))
}

// recvFrame returns the inner packet of the next data frame in d, or nil.
func (a *agent) recvFrame(d time.Duration) []byte {
	a.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	b, err := a.qc.ReceiveDatagram(ctx)
	if err != nil {
		return nil
	}
	vni, inner, err := peerconn.DecodeData(b)
	require.NoError(a.t, err)
	require.EqualValues(a.t, netID, vni)
	return inner
}

// noFrame checks that no data frame comes in d.
func (a *agent) noFrame(d time.Duration) {
	a.t.Helper()
	if b := a.recvFrame(d); b != nil {
		a.t.Fatalf("unexpected data frame of %d bytes", len(b))
	}
}

// pspSocket returns a new UDP socket for probes and PSP packets.
func pspSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// probe sends a path probe with counter from sock to the data port and returns the source
// address that the reply saw.
func (a *agent) probe(e *env, sock *net.UDPConn, counter uint64) netip.AddrPort {
	a.t.Helper()
	var txID [12]byte
	_, _ = rand.Read(txID[:])
	b := p2p.AppendProbe(nil, p2p.Probe{SID: a.keys.SID, TxID: txID, Counter: counter}, 0, &a.keys.Dialer)
	_, err := sock.WriteToUDP(b, e.data)
	require.NoError(a.t, err)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(wait)
	for {
		require.NoError(a.t, sock.SetReadDeadline(deadline))
		n, err := sock.Read(buf)
		require.NoError(a.t, err, "no probe reply")
		pr, err := p2p.OpenProbe(buf[:n], &a.keys.Listener)
		if err == nil && pr.Reply && pr.TxID == txID {
			return pr.Seen
		}
	}
}

// keepPath sends a BFD packet from sock each 500 ms, so that the PSP path check of the relay
// stays up. It does not move the PSP address.
func (a *agent) keepPath(e *env, sock *net.UDPConn) {
	check := p2p.NewCheck(p2p.RoleAgent, time.Second)
	counter := a.probes
	stop := make(chan struct{})
	done := make(chan struct{})
	a.t.Cleanup(func() {
		close(stop)
		<-done
		check.Close()
	})
	go func() {
		defer close(done)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			b := check.Append(nil, p2p.Probe{SID: a.keys.SID, Counter: counter}, &a.keys.Dialer)
			_, _ = sock.WriteToUDP(b, e.data)
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
}

// toPSP probes from sock and changes the connection to PSP mode with one agent SA. It returns the
// relay offer.
func (a *agent) toPSP(e *env, sock *net.UDPConn, generation uint64) *dpv1.KeysRequest {
	a.t.Helper()
	a.probes++
	seen := a.probe(e, sock, a.probes)
	require.Equal(a.t, sock.LocalAddr().(*net.UDPAddr).AddrPort(), seen)
	if a.rxSPI == 0 {
		a.rxSPI = 0x1001
	}
	a.rxKey = make([]byte, 16)
	_, _ = rand.Read(a.rxKey)
	before := len(a.all(isRekey))
	res, err := a.rc.Rekey(context.Background(), offer(a.rxSPI, a.rxKey, netID, generation))
	require.NoError(a.t, err)
	require.Empty(a.t, res.GetRefusedSpis())
	rk := a.waitMsg(before+1, isRekey).GetRekey()
	sas := rk.GetOffer().GetSas()
	require.Len(a.t, sas, 1)
	a.txSPI, a.txKey = sas[0].GetSpi(), sas[0].GetKey()
	return rk
}

func offer(spi uint32, key []byte, vni uint32, generation uint64) *dpv1.KeysRequest {
	return &dpv1.KeysRequest{
		Op: &dpv1.KeysRequest_Offer{Offer: &dpv1.OfferSAs{Sas: []*dpv1.SA{{
			Spi: spi, Key: key, Vni: vni, ExpiresIn: durationpb.New(time.Hour),
		}}}},
		Generation: generation,
	}
}

func isRekey(m *dpv1.SessionResponse) bool { return m.GetRekey() != nil }

// sendPSP seals inner with the relay SA and sends it from sock to the data port.
func (a *agent) sendPSP(e *env, sock *net.UDPConn, inner []byte) {
	a.t.Helper()
	aead, err := psp.NewAEAD(a.txKey)
	require.NoError(a.t, err)
	a.seq++
	h := psp.Header{Version: psp.AESGCM128, SPI: a.txSPI, IV: uint64(a.seq), VNI: netID, Flags: psp.FlagSeq, Seq: a.seq}
	out := make([]byte, len(inner)+psp.Overhead)
	n, err := psp.Seal(aead, h, out, inner)
	require.NoError(a.t, err)
	_, err = sock.WriteToUDP(out[:n], e.data)
	require.NoError(a.t, err)
}

// recvPSP returns the inner packet of the next PSP packet on sock in d, or nil. It skips the
// path probes of the relay.
func (a *agent) recvPSP(sock *net.UDPConn, d time.Duration) []byte {
	a.t.Helper()
	buf := make([]byte, 2048)
	deadline := time.Now().Add(d)
	for {
		require.NoError(a.t, sock.SetReadDeadline(deadline))
		n, err := sock.Read(buf)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil
		}
		require.NoError(a.t, err)
		if n > 0 && buf[0] == p2p.TypeProbe {
			continue
		}
		h, err := psp.ParseHeader(buf[:n])
		require.NoError(a.t, err)
		require.Equal(a.t, a.rxSPI, h.SPI)
		require.EqualValues(a.t, netID, h.VNI)
		aead, err := psp.NewAEAD(a.rxKey)
		require.NoError(a.t, err)
		inner, err := psp.OpenInPlace(aead, buf[:n])
		require.NoError(a.t, err)
		return slices.Clone(inner)
	}
}

// statsOf returns the stats of attachment id, or nil.
func (e *env) statsOf(id string) *relay.AttachmentStats {
	for _, s := range e.r.AttachmentStats() {
		if s.ID == id {
			return &s
		}
	}
	return nil
}

// waitEnd waits for the final stats of attachment id.
func (e *env) waitEnd(t *testing.T, id string) relay.AttachmentStats {
	t.Helper()
	timeout := time.After(wait)
	for {
		select {
		case s := <-e.ends:
			if s.ID == id {
				return s
			}
		case <-timeout:
			t.Fatalf("no end of attachment %s", id)
		}
	}
}
