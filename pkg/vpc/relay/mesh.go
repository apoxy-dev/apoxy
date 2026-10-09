// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// meshRevision is the first revision with the Open call of the mesh.
	meshRevision = 3
	// meshKeepAlive and meshIdleTimeout are the QUIC timers of a mesh session
	// on both relays. A relay sees a lost session when the idle timeout ends.
	meshKeepAlive   = time.Second
	meshIdleTimeout = 5 * time.Second
	// meshOpenTimeout limits the dial and the Open call of a new session.
	meshOpenTimeout = 5 * time.Second
	// A relay dials again after redialMin. The wait doubles after each failed
	// dial up to redialMax, and each wait gets up to 50% more at random.
	redialMin = 200 * time.Millisecond
	redialMax = 10 * time.Second
	// meshDownAfter is the time from the end of a session until its member is
	// down, if no new session opens. A shorter loss changes nothing for agents.
	meshDownAfter = 3 * time.Second
)

var (
	errMeshStopped = errors.New("mesh stopped")
	errNotMember   = errors.New("relay is not a member")
)

// MeshMember is another relay of the mesh.
type MeshMember struct {
	// Name is the relay name. Each relay process has its own name.
	Name string
	// Addr is the UDP address of the relay socket.
	Addr netip.AddrPort
}

// MeshVerify checks the certificate chain (leaf first) of the relay at from,
// which tells that its relay name is name. An error refuses the session.
type MeshVerify func(chain []*x509.Certificate, name string, from netip.AddrPort) error

// MeshConfig is the data of the relay host for the mesh.
type MeshConfig struct {
	// Relay is the ID and the agent addresses of this relay. Open gives it to
	// the other relays, which give it to their agents when they drain.
	Relay *dp.RelayRef
	// TLS has the certificate of this relay as a server and as a client. The
	// mesh adds the ALPN and TLS 1.3, and requires a certificate from a dialer.
	TLS *tls.Config
	// Verify checks the other relay after the handshake. It gets the name and
	// address of the dialed member, or the name from Open and the source address.
	Verify MeshVerify
	// Home returns the name of the home relay of the overlay address addr of vpc,
	// or "". It is optional, and it must not call the Router or the Mesh.
	Home func(vpc VPCKey, addr netip.Addr) string
	// Snapshot returns the bytes of the host snapshot for a member that asks, or nil.
	// It is optional. The mesh calls it one time for each call of a member and reads the
	// bytes until the stream ends, so return bytes that are ready and that do not change.
	Snapshot func() []byte
}

// MeshDown is the reason that a member is down.
type MeshDown uint8

const (
	// MeshLost tells that the session ended and no new session opened in time.
	MeshLost MeshDown = iota + 1
	// MeshRestart tells that the member stops on purpose. Its attachments are gone.
	MeshRestart
	// MeshRemoved tells that the member left the member set. A member that was
	// down before it left gets this change too.
	MeshRemoved
)

func (d MeshDown) String() string {
	switch d {
	case MeshLost:
		return "lost"
	case MeshRestart:
		return "restart"
	case MeshRemoved:
		return "removed"
	}
	return "none"
}

// MeshChange tells that a member is up or down.
type MeshChange struct {
	// Name is the relay name of the member.
	Name string
	Up   bool
	// Down is the reason of a down change.
	Down MeshDown
}

// Mesh keeps one mesh session (ALPN apoxy-mesh/1) with each other relay of
// the member set. Of two relays, the relay with the lower name dials.
type Mesh struct {
	dp.UnimplementedMeshServer

	name string
	cfg  MeshConfig
	tls  *tls.Config
	ver  *dp.Version // Protocol version of the relay.
	mux  *rpc.Mux
	// trunk has the trunk keys of the members. It is nil before SetRouter.
	trunk atomic.Pointer[trunk]

	mu       sync.Mutex
	members  map[string]*meshMember
	sessions map[*rpc.Conn]*MeshSession // Sessions before and after Open.
	ctx      context.Context            // Context of Run. Nil before Run.
	tr       *quic.Transport
	quic     *quic.Config
	stopped  bool
	wg       sync.WaitGroup // Dial loops and the sessions that this relay dialed.
	events   []meshEvent    // Changes that wait for the hooks, in order.
	wake     chan struct{}  // Has room for 1: events has changes.

	onChange   []func(MeshChange)
	onSession  []func(*MeshSession)
	onDatagram func(*MeshSession, []byte)

	pres *presence // Attachments that the members and this relay share.
	// away has the RelayRef of each member that agents must visit, by relay name.
	away atomic.Pointer[map[string]*dp.RelayRef]
}

// meshMember is the state of one member. Mesh.mu guards its fields.
type meshMember struct {
	MeshMember
	sess *MeshSession // Open session, or nil.
	// relay is the RelayRef of the last session. It is nil after a RESTART close.
	relay *dp.RelayRef
	up    bool
	ends  uint64             // Sessions that ended. A down timer is for one value.
	stop  context.CancelFunc // Ends the dial loop. Nil if no loop runs.
}

// meshEvent is one change for the hooks: a new session, or else change.
type meshEvent struct {
	sess   *MeshSession
	change MeshChange
}

// MeshSession is one mesh session with a member.
type MeshSession struct {
	qc     quic.Connection
	conn   *rpc.Conn
	client dp.MeshClient
	dialer bool          // This relay dialed the session.
	ready  chan struct{} // Closed when Open passes.

	// Set under Mesh.mu before ready closes.
	name    string
	relay   *dp.RelayRef
	version *dp.Version
}

// Name returns the relay name of the member.
func (s *MeshSession) Name() string { return s.name }

// Relay returns the ID and the agent addresses of the member, from Open.
func (s *MeshSession) Relay() *dp.RelayRef { return s.relay }

// Version returns the protocol version of the member, from Open.
func (s *MeshSession) Version() *dp.Version { return s.version }

// Client returns the client for calls to the member.
func (s *MeshSession) Client() dp.MeshClient { return s.client }

// Context returns a context that ends when the session ends.
func (s *MeshSession) Context() context.Context { return s.qc.Context() }

// SendDatagram sends b to the member in one QUIC DATAGRAM frame.
func (s *MeshSession) SendDatagram(b []byte) error { return s.qc.SendDatagram(b) }

func (s *MeshSession) close(code dp.MeshCloseCode, msg string) {
	_ = s.qc.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// NewMesh returns the mesh of the relay with name. It has no members until
// SetMembers, and it dials after Run.
func NewMesh(name string, cfg MeshConfig) (*Mesh, error) {
	switch {
	case name == "":
		return nil, errors.New("mesh needs the relay name")
	case cfg.TLS == nil:
		return nil, errors.New("mesh needs a TLS config")
	case cfg.Verify == nil:
		return nil, errors.New("mesh needs a check of the other relay")
	}
	m := &Mesh{
		name:     name,
		cfg:      cfg,
		ver:      dp.LocalVersion(build.BuildVersion),
		mux:      rpc.NewMux(),
		members:  map[string]*meshMember{},
		sessions: map[*rpc.Conn]*MeshSession{},
		wake:     make(chan struct{}, 1),
	}
	m.tls = m.TLSConfig()
	m.pres = newPresence(m)
	m.onSession, m.onChange = append(m.onSession, m.pres.opened), append(m.onChange, m.pres.down)
	dp.RegisterMeshServer(m.mux, m)
	return m, nil
}

// TLSConfig returns the TLS config of the relay listener for apoxy-mesh/1.
func (m *Mesh) TLSConfig() *tls.Config {
	c := m.cfg.TLS.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{dp.ALPNMesh}
	// Verify needs the certificate of the relay that dials.
	if c.ClientAuth != tls.RequireAndVerifyClientCert {
		c.ClientAuth = tls.RequireAnyClientCert
	}
	return c
}

// quicConfig returns a copy of base with the timers of a mesh session.
func (m *Mesh) quicConfig(base *quic.Config) *quic.Config {
	c := &quic.Config{}
	if base != nil {
		c = base.Clone()
	}
	c.KeepAlivePeriod = meshKeepAlive
	c.MaxIdleTimeout = meshIdleTimeout
	c.EnableDatagrams = true
	c.GetConfigForClient = nil
	if c.Tracer == nil {
		// The RTT metric of a member reads what this tracer keeps.
		c.Tracer = TraceRTT
	}
	return c
}

// ListenConfig returns a copy of base for the relay listener. QUIC gives the
// config before the ALPN, so the address of a member selects the mesh timers.
func (m *Mesh) ListenConfig(base *quic.Config) *quic.Config {
	c := &quic.Config{}
	if base != nil {
		c = base.Clone()
	}
	next := c.GetConfigForClient
	c.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
		conf := base
		if next != nil {
			var err error
			if conf, err = next(info); err != nil {
				return nil, err
			}
		}
		if m.hasAddr(addrPort(info.RemoteAddr)) {
			return m.quicConfig(conf), nil
		}
		return conf, nil
	}
	return c
}

func (m *Mesh) hasAddr(a netip.AddrPort) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mem := range m.members {
		if mem.Addr == a {
			return true
		}
	}
	return false
}

// OnChange adds fn, which gets each up and down change of a member, in order.
// Run calls fn, so fn must not wait. Call OnChange before Run.
func (m *Mesh) OnChange(fn func(MeshChange)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = append(m.onChange, fn)
}

// OnSession adds fn, which gets each session that passed Open, after the up
// change of its member. Run calls fn, so fn must not wait. Call it before Run.
func (m *Mesh) OnSession(fn func(*MeshSession)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onSession = append(m.onSession, fn)
}

// OnDatagram sets fn, which gets the QUIC DATAGRAM frames of each session
// after Open passes. Call it before Run, and not on a mesh with SetRouter.
func (m *Mesh) OnDatagram(fn func(s *MeshSession, b []byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDatagram = fn
}

// SetMembers replaces the member set. A member that left or has a new address
// loses its session, and the mesh dials each new member with a higher name.
func (m *Mesh) SetMembers(members []MeshMember) {
	want := make(map[string]MeshMember, len(members))
	for _, mem := range members {
		if mem.Name == "" || mem.Name == m.name || !mem.Addr.IsValid() {
			continue
		}
		mem.Addr = netip.AddrPortFrom(mem.Addr.Addr().Unmap(), mem.Addr.Port())
		want[mem.Name] = mem
	}
	var closed []*MeshSession
	m.mu.Lock()
	for name, mem := range m.members {
		if w, ok := want[name]; ok && w == mem.MeshMember {
			continue
		}
		// A new address is a new relay process, so its old session ends too.
		delete(m.members, name)
		if mem.stop != nil {
			mem.stop()
		}
		if mem.sess != nil {
			closed = append(closed, mem.sess)
			mem.sess = nil
		}
		m.down(mem, MeshRemoved)
	}
	for name, w := range want {
		if m.members[name] == nil {
			mem := &meshMember{MeshMember: w}
			m.members[name] = mem
			m.startDial(mem)
		}
	}
	m.setAway()
	m.mu.Unlock()
	for _, s := range closed {
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, "relay is not a member at this address")
	}
}

// Up reports whether member name is up: it has a session, or its last session
// ended a short time ago and it did not tell that it stops.
func (m *Mesh) Up(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	mem := m.members[name]
	return mem != nil && mem.up
}

// Session returns the open session with member name, or nil.
func (m *Mesh) Session(name string) *MeshSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mem := m.members[name]; mem != nil {
		return mem.sess
	}
	return nil
}

// hasRelay reports whether id is the relay ID of a member: the last session of
// the member gave it in Open, and that session did not close with RESTART.
func (m *Mesh) hasRelay(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mem := range m.members {
		if id != "" && mem.relay.GetId() == id {
			return true
		}
	}
	return false
}

// setAway finds the members that agents must visit: a member that is down, and
// whose last session gave a relay ID that no other relay has. Mesh.mu must be held.
func (m *Mesh) setAway() {
	away := map[string]*dp.RelayRef{}
	for name, mem := range m.members {
		// A member with no session stays up for meshDownAfter. A member that closed
		// its session with RESTART has no relay.
		id := mem.relay.GetId()
		if mem.up || id == "" || id == m.cfg.Relay.GetId() {
			continue
		}
		// An agent cannot choose one of two relays that have the same ID.
		shared := false
		for _, o := range m.members {
			shared = shared || o != mem && o.relay.GetId() == id
		}
		if !shared {
			away[name] = mem.relay
		}
	}
	m.away.Store(&away)
}

// awayRef returns the RelayRef of the member name if agents must visit it, or
// nil. It takes no lock.
func (m *Mesh) awayRef(name string) *dp.RelayRef {
	if away := m.away.Load(); away != nil {
		return (*away)[name]
	}
	return nil
}

// homeOf returns the name of the home relay of addr from the host, or "". It
// asks the host only while agents must visit a member. It takes no lock.
func (m *Mesh) homeOf(vpc VPCKey, addr netip.Addr) string {
	if away := m.away.Load(); m.cfg.Home == nil || away == nil || len(*away) == 0 {
		return ""
	}
	return m.cfg.Home(vpc, addr)
}

// Alternates returns the relays that an agent of this relay can move to: each
// member with an open session whose Open gave agent addresses, in name order.
func (m *Mesh) Alternates() []*dp.RelayRef {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.members))
	for name, mem := range m.members {
		if mem.sess != nil && len(mem.sess.relay.GetAddresses()) > 0 {
			names = append(names, name)
		}
	}
	// The mesh has no measure of distance, so the order is the same each time.
	slices.Sort(names)
	var out []*dp.RelayRef
	for _, name := range names {
		ref := m.members[name].sess.relay
		// Relays behind one name give the same ID and the same addresses.
		if !slices.ContainsFunc(out, func(o *dp.RelayRef) bool { return proto.Equal(o, ref) }) {
			out = append(out, ref)
		}
	}
	return out
}

// SessionOf returns the session of the call that a handler of the Mesh
// service serves. A call that comes before the end of Open waits for it.
func (m *Mesh) SessionOf(ctx context.Context) (*MeshSession, error) {
	m.mu.Lock()
	s := m.sessions[rpc.ConnFromContext(ctx)]
	m.mu.Unlock()
	if s == nil {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "call is not on a mesh session")
	}
	select {
	case <-s.ready:
		return s, nil
	case <-ctx.Done():
		return nil, rpc.Errorf(rpc.FailedPrecondition, "mesh session is not open")
	}
}

// Run dials from tr, the relay socket transport, with base config conf, and
// calls the hooks until ctx ends. Then it closes each session with RESTART.
func (m *Mesh) Run(ctx context.Context, tr *quic.Transport, conf *quic.Config) {
	m.mu.Lock()
	m.ctx, m.tr, m.quic = ctx, tr, m.quicConfig(conf)
	for _, mem := range m.members {
		m.startDial(mem)
	}
	m.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			m.stop()
			return
		case <-m.wake:
			m.deliver()
		}
	}
}

// stop closes all sessions and waits for the dial loops.
func (m *Mesh) stop() {
	m.mu.Lock()
	m.stopped = true
	m.events = nil
	sessions := make([]*MeshSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART, "relay stops")
	}
	m.wg.Wait()
}

// notify gives e to the hooks later, in order. Mesh.mu must be held.
func (m *Mesh) notify(e meshEvent) {
	if m.stopped {
		return
	}
	m.events = append(m.events, e)
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// deliver calls the hooks for the changes that wait.
func (m *Mesh) deliver() {
	m.mu.Lock()
	events, onChange, onSession := m.events, m.onChange, m.onSession
	m.events = nil
	m.mu.Unlock()
	for _, e := range events {
		if e.sess != nil {
			for _, fn := range onSession {
				fn(e.sess)
			}
			continue
		}
		for _, fn := range onChange {
			fn(e.change)
		}
	}
}

// down makes mem down for reason. Mesh.mu must be held.
func (m *Mesh) down(mem *meshMember, reason MeshDown) {
	// The hooks keep data of a member that was up before, until it leaves the set.
	if !mem.up && (reason != MeshRemoved || mem.ends == 0) {
		return
	}
	mem.up = false
	m.notify(meshEvent{change: MeshChange{Name: mem.Name, Down: reason}})
	slog.Info("Mesh member is down", "relay", mem.Name, "reason", reason.String())
}

// startDial starts the dial loop of mem if this relay dials it and Run runs.
// Mesh.mu must be held.
func (m *Mesh) startDial(mem *meshMember) {
	if m.ctx == nil || m.stopped || mem.stop != nil || m.name > mem.Name {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	mem.stop = cancel
	m.wg.Go(func() { m.dialLoop(ctx, mem) })
}

// redial gives the waits before the dials of one member.
type redial struct{ wait time.Duration }

// next returns the wait before the next dial. The random part stops the
// relays from dialing all at one time.
func (b *redial) next() time.Duration {
	b.wait = min(max(2*b.wait, redialMin), redialMax)
	return b.wait + rand.N(b.wait/2+1)
}

// dialLoop keeps a session to mem until ctx ends.
func (m *Mesh) dialLoop(ctx context.Context, mem *meshMember) {
	var wait redial
	for {
		s, err := m.dial(ctx, mem)
		switch {
		case err == nil:
			wait = redial{}
			select {
			case <-s.qc.Context().Done():
			case <-ctx.Done():
				return
			}
		case ctx.Err() != nil:
			return
		case wait.wait == 0:
			slog.Warn("Failed to open mesh session", "relay", mem.Name, "addr", mem.Addr, "error", err)
		default:
			slog.Debug("Failed to open mesh session", "relay", mem.Name, "addr", mem.Addr, "error", err)
		}
		t := time.NewTimer(wait.next())
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return
		}
	}
}

// dial opens a session to mem: the handshake, the check of the certificate
// and the Open call.
func (m *Mesh) dial(ctx context.Context, mem *meshMember) (*MeshSession, error) {
	ctx, cancel := context.WithTimeout(ctx, meshOpenTimeout)
	defer cancel()
	m.mu.Lock()
	tr, conf := m.tr, m.quic
	m.mu.Unlock()
	// A dialed connection keeps the values of ctx, so it gets the place for its RTT here.
	ctx, _ = TraceContext(ctx, nil)
	qc, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(mem.Addr), m.tls, conf)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	s := m.newSession(qc, true)
	if err := m.cfg.Verify(qc.ConnectionState().TLS.PeerCertificates, mem.Name, addrPort(qc.RemoteAddr())); err != nil {
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, "relay certificate rejected")
		return nil, fmt.Errorf("relay certificate rejected: %w", err)
	}
	if !m.track(s) {
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART, "relay stops")
		return nil, errMeshStopped
	}
	res, err := s.client.Open(ctx, &dp.MeshOpenRequest{Version: m.ver, Name: m.name, Relay: m.cfg.Relay})
	if err != nil {
		if code, reason, ok := remoteClose(qc, err); ok {
			err = fmt.Errorf("relay closed the session with %v: %s", code, reason)
		}
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "")
		return nil, fmt.Errorf("open: %w", err)
	}
	if got := res.GetName(); got != mem.Name {
		err := fmt.Errorf("relay %q is not the member %q that this relay dialed", got, mem.Name)
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, err.Error())
		return nil, err
	}
	if err := m.checkRevision(res.GetVersion()); err != nil {
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE, err.Error())
		return nil, err
	}
	if err := m.admit(s, mem.Name, mem, res.GetVersion(), res.GetRelay()); err != nil {
		s.close(admitCloseCode(err), err.Error())
		return nil, err
	}
	return s, nil
}

// admitCloseCode returns the close code for an error of admit.
func admitCloseCode(err error) dp.MeshCloseCode {
	switch {
	case errors.Is(err, errNotMember):
		return dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER
	case errors.Is(err, errMeshStopped):
		return dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART
	}
	return dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED
}

// remoteClose returns the code and the reason with which the other relay
// closed qc. err is the error of a call on qc.
func remoteClose(qc quic.Connection, err error) (dp.MeshCloseCode, string, bool) {
	var ae *quic.ApplicationError
	// quic-go ends the call streams before it sets the close cause.
	if !errors.As(err, &ae) && !errors.As(context.Cause(qc.Context()), &ae) {
		return 0, "", false
	}
	return dp.MeshCloseCode(ae.ErrorCode), ae.ErrorMessage, ae.Remote
}

// checkRevision refuses a relay whose revision is below the minimum of this
// relay, or from before the Open call.
func (m *Mesh) checkRevision(v *dp.Version) error {
	if got, least := v.GetRevision(), max(m.ver.GetMinRevision(), meshRevision); got < least {
		return fmt.Errorf("relay revision %d is below the minimum %d", got, least)
	}
	return nil
}

func (m *Mesh) newSession(qc quic.Connection, dialer bool) *MeshSession {
	conn := rpc.NewConn(qc, m.mux)
	return &MeshSession{qc: qc, conn: conn, client: dp.NewMeshClient(conn), dialer: dialer, ready: make(chan struct{})}
}

// track keeps s until its connection closes, so that the handlers find it.
// It returns false after the mesh stopped.
func (m *Mesh) track(s *MeshSession) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return false
	}
	m.sessions[s.conn] = s
	context.AfterFunc(s.qc.Context(), func() { m.ended(s) })
	if s.dialer {
		// The member can call this relay before the answer to Open arrives.
		ctx := m.ctx
		m.wg.Go(func() { m.serve(ctx, s) })
	}
	return true
}

// serve answers the calls of the other relay on s until the session ends.
// When ctx ends, this relay stops.
func (m *Mesh) serve(ctx context.Context, s *MeshSession) {
	_ = s.conn.Serve(ctx)
	if ctx.Err() != nil {
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART, "relay stops")
		return
	}
	s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "")
}

// ServeConn serves a session that another relay dialed until it closes or ctx
// ends. The host calls it for an apoxy-mesh/1 connection after the handshake.
func (m *Mesh) ServeConn(ctx context.Context, qc quic.Connection) {
	s := m.newSession(qc, false)
	if alpn := qc.ConnectionState().TLS.NegotiatedProtocol; alpn != dp.ALPNMesh {
		slog.Info("Refused mesh session", "remote", qc.RemoteAddr(), "reason", fmt.Sprintf("ALPN %q is not %s", alpn, dp.ALPNMesh))
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "not a mesh session")
		return
	}
	if !m.track(s) {
		s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART, "relay stops")
		return
	}
	// A relay that does not call Open in time does not keep its connection.
	t := time.AfterFunc(meshOpenTimeout, func() {
		select {
		case <-s.ready:
		default:
			s.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "no Open call")
		}
	})
	defer t.Stop()
	m.serve(ctx, s)
}

// Open answers the first call of a relay that dialed. It checks the
// certificate, the name and the revision of that relay.
func (m *Mesh) Open(ctx context.Context, req *dp.MeshOpenRequest) (*dp.MeshOpenResponse, error) {
	m.mu.Lock()
	s := m.sessions[rpc.ConnFromContext(ctx)]
	m.mu.Unlock()
	if s == nil || s.dialer {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "only the relay that dialed calls Open")
	}
	select {
	case <-s.ready:
		return nil, rpc.Errorf(rpc.FailedPrecondition, "mesh session is already open")
	default:
	}
	name, from := req.GetName(), addrPort(s.qc.RemoteAddr())
	// The other relay gets msg as the close reason. detail stays in the log.
	refuse := func(code dp.MeshCloseCode, status rpc.Code, msg string, detail ...any) error {
		slog.Info("Refused mesh session", append([]any{"relay", name, "remote", from, "reason", msg}, detail...)...)
		s.close(code, msg)
		return rpc.Errorf(status, "%s", msg)
	}
	// The certificate check is first, so that only a relay with a good
	// certificate learns which names are members.
	if err := m.cfg.Verify(s.qc.ConnectionState().TLS.PeerCertificates, name, from); err != nil {
		return nil, refuse(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, rpc.PermissionDenied, "relay certificate rejected", "error", err)
	}
	if m.member(name) == nil {
		return nil, refuse(dp.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, rpc.PermissionDenied, fmt.Sprintf("relay %q is not a member", name))
	}
	// One session for two relays: only the relay with the lower name dials.
	if name > m.name {
		return nil, refuse(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, rpc.FailedPrecondition, "the relay with the lower name dials the mesh session")
	}
	if err := m.checkRevision(req.GetVersion()); err != nil {
		return nil, refuse(dp.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE, rpc.FailedPrecondition, err.Error())
	}
	if err := m.admit(s, name, nil, req.GetVersion(), req.GetRelay()); err != nil {
		return nil, refuse(admitCloseCode(err), rpc.FailedPrecondition, err.Error())
	}
	return &dp.MeshOpenResponse{Version: m.ver, Name: m.name, Relay: m.cfg.Relay}, nil
}

func (m *Mesh) member(name string) *meshMember {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.members[name]
}

// admit makes s the session of member name in place of an older one. want is
// the dialed member, or nil. It fails if the member, s or the mesh is gone.
func (m *Mesh) admit(s *MeshSession, name string, want *meshMember, v *dp.Version, ref *dp.RelayRef) error {
	m.mu.Lock()
	mem := m.members[name]
	var err error
	switch {
	case m.stopped:
		err = errMeshStopped
	case m.sessions[s.conn] != s:
		err = errors.New("mesh session closed")
	case mem == nil || want != nil && mem != want:
		err = fmt.Errorf("%w: %q", errNotMember, name)
	case mem.sess == s:
		err = errors.New("mesh session is already open")
	}
	if err != nil {
		m.mu.Unlock()
		return err
	}
	old := mem.sess
	mem.sess, mem.relay = s, ref
	s.name, s.version, s.relay = name, v, ref
	close(s.ready)
	if !mem.up {
		mem.up = true
		m.notify(meshEvent{change: MeshChange{Name: name, Up: true}})
	}
	m.setAway()
	m.notify(meshEvent{sess: s})
	onDatagram := m.onDatagram
	m.mu.Unlock()
	if old != nil {
		old.close(dp.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "a new session replaced this one")
	}
	if onDatagram != nil {
		go m.readDatagrams(s, onDatagram)
	}
	slog.Info("Opened mesh session", "relay", name, "remote", s.qc.RemoteAddr(), "dialer", s.dialer,
		"revision", v.GetRevision(), "build", buildLabel(v.GetBuild()))
	return nil
}

// readDatagrams gives the datagrams of s to fn until the session ends.
func (m *Mesh) readDatagrams(s *MeshSession, fn func(*MeshSession, []byte)) {
	for {
		b, err := s.qc.ReceiveDatagram(s.qc.Context())
		if err != nil {
			return
		}
		fn(s, b)
	}
}

// ended removes s after its connection closed. The member of an open session
// is down after meshDownAfter with no new session, or at once after RESTART.
func (m *Mesh) ended(s *MeshSession) {
	cause := context.Cause(s.qc.Context())
	m.mu.Lock()
	delete(m.sessions, s.conn)
	mem := m.members[s.name]
	if mem == nil || mem.sess != s {
		m.mu.Unlock()
		return
	}
	mem.sess = nil
	mem.ends++
	if code, _, remote := remoteClose(s.qc, cause); remote && code == dp.MeshCloseCode_MESH_CLOSE_CODE_RESTART {
		// The grants that the member signed before are for attachments that are gone.
		mem.relay = nil
		m.down(mem, MeshRestart)
	} else {
		ends := mem.ends
		time.AfterFunc(meshDownAfter, func() { m.expire(mem, ends) })
	}
	m.setAway()
	m.mu.Unlock()
	slog.Info("Closed mesh session", "relay", s.name, "reason", cause)
}

// expire makes mem down if it got no session after the end of session ends.
func (m *Mesh) expire(mem *meshMember, ends uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.members[mem.Name] == mem && mem.sess == nil && mem.ends == ends {
		m.down(mem, MeshLost)
		m.setAway()
	}
}
