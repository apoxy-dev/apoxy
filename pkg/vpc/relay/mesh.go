// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/psp/keyproto"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// meshRevision is the first revision of the mesh in this form: one Presence call for each
	// tenant, with acks. A relay closes a mesh session with an older relay with UPGRADE.
	meshRevision = 22
	// meshKeepAlive and meshIdleTimeout are the QUIC timers of a mesh session on both relays. A
	// relay sees a lost session when the idle timeout ends.
	meshKeepAlive   = time.Second
	meshIdleTimeout = 5 * time.Second
	// meshOpenTimeout limits the dial and the Open call of a new session.
	meshOpenTimeout = 5 * time.Second
	// meshStreams is the most calls that the other relay can have open on a mesh session: one
	// Presence call for each tenant, and the short calls.
	meshStreams = 1 << 14
	// A relay dials again after redialMin. The wait doubles after each failed dial up to
	// redialMax, and each wait gets up to 50% more at random.
	redialMin = 200 * time.Millisecond
	redialMax = 10 * time.Second
	// snapshotPartSize is the most bytes of one part of a snapshot. A call message holds 4 MiB.
	snapshotPartSize = 1 << 20
	// maxSnapshotSize is the most bytes of a snapshot that a relay sends or takes.
	maxSnapshotSize = 64 << 20
	// snapshotTimeout limits the Snapshot call to one member.
	snapshotTimeout = 10 * time.Second
)

// MeshMember is another relay of the mesh.
type MeshMember struct {
	// Name is the relay name. Each relay process has its own name.
	Name string
	// Addr is the UDP address of the QUIC socket of the relay. Its data port is at the same IP
	// address, at the port that it gives in Open.
	Addr netip.AddrPort
}

// MeshVerify checks the certificate chain (leaf first) of the relay at from, which tells that its
// relay name is name. An error refuses the session.
type MeshVerify func(chain []*x509.Certificate, name string, from netip.AddrPort) error

// MeshConfig is the data of the relay host for the mesh. Open gives Config.Relay to the other
// relays, which give it to their agents.
type MeshConfig struct {
	// TLS has the certificate of this relay as a server and as a client. The mesh adds the ALPN
	// and TLS 1.3, and requires a certificate from a dialer.
	TLS *tls.Config
	// Verify checks the other relay after the handshake. It gets the name and address of the
	// dialed member, or the name from Open and the source address.
	Verify MeshVerify
	// Snapshot returns the host snapshot for a member that asks, or nil. The mesh reads the bytes
	// until the stream ends, so they must not change. It is optional.
	Snapshot func() []byte
}

// MeshDown is the reason that a member is down.
type MeshDown uint8

const (
	// MeshLost tells that the session ended.
	MeshLost MeshDown = iota + 1
	// MeshRestart tells that the member stops on purpose. Its attachments are gone.
	MeshRestart
	// MeshRemoved tells that the member left the member set. A member that was down before it
	// left gets this change too.
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

// MeshSession is one open mesh session with a member.
type MeshSession struct {
	name    string
	relay   *dpv1.RelayRef
	version *dpv1.Version
	qc      *quic.Conn // Its stats give the RTT of the session.
}

// Name returns the relay name of the member.
func (s *MeshSession) Name() string { return s.name }

// Relay returns the ID and the agent addresses of the member, from Open.
func (s *MeshSession) Relay() *dpv1.RelayRef { return s.relay }

// Version returns the protocol version of the member, from Open.
func (s *MeshSession) Version() *dpv1.Version { return s.version }

// meshState is the mesh config of a router, with the server of its calls.
type meshState struct {
	name string
	cfg  MeshConfig
	tls  *tls.Config
	tr   *quic.Transport
	quic *quic.Config
	mux  *rpc.Mux
}

// SetMesh makes the relay with the relay name name keep one mesh session (ALPN apoxy-mesh/1)
// with each member of SetMembers. Of two relays, the relay with the lower name dials, from tr,
// the transport of its listener, with the QUIC config base. Call it before TLSConfig,
// ListenConfig and Run.
func (r *Router) SetMesh(name string, cfg MeshConfig, tr *quic.Transport, base *quic.Config) error {
	switch {
	case name == "":
		return errors.New("mesh needs the relay name")
	case cfg.TLS == nil:
		return errors.New("mesh needs a TLS config")
	case cfg.Verify == nil:
		return errors.New("mesh needs a check of the other relay")
	case tr == nil:
		return errors.New("mesh needs a QUIC transport")
	}
	t := cfg.TLS.Clone()
	t.MinVersion = tls.VersionTLS13
	t.NextProtos = []string{dpv1.ALPNMesh}
	// Verify needs the certificate of the relay that dials.
	if t.ClientAuth != tls.RequireAndVerifyClientCert {
		t.ClientAuth = tls.RequireAnyClientCert
	}
	m := &meshState{name: name, cfg: cfg, tls: t, tr: tr, quic: meshQUICConfig(base), mux: rpc.NewMux()}
	dpv1.RegisterMeshServer(m.mux, meshServer{r: r})
	r.mesh = m
	return nil
}

// meshQUICConfig returns a copy of base with the timers of a mesh session.
func meshQUICConfig(base *quic.Config) *quic.Config {
	c := &quic.Config{}
	if base != nil {
		c = base.Clone()
	}
	c.KeepAlivePeriod = meshKeepAlive
	c.MaxIdleTimeout = meshIdleTimeout
	c.MaxIncomingStreams = meshStreams
	c.GetConfigForClient = nil
	return c
}

// ListenConfig returns a copy of base for the listener of the relay. QUIC gives the config before
// the ALPN, so the address of a member selects the mesh timers.
func (r *Router) ListenConfig(base *quic.Config) *quic.Config {
	c := &quic.Config{}
	if base != nil {
		c = base.Clone()
	}
	if r.mesh == nil {
		return c
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
		if r.memberAddr(addrPort(info.RemoteAddr)) {
			return meshQUICConfig(conf), nil
		}
		return conf, nil
	}
	return c
}

// memberAddr reports whether a is the address of a member of the list of the host.
func (r *Router) memberAddr(a netip.AddrPort) bool {
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	if l := r.members.Load(); l != nil {
		for _, m := range *l {
			if m.Addr == a {
				return true
			}
		}
	}
	return false
}

// SetMembers replaces the member set. A member that left or has a new address loses its session,
// and the relay dials each new member with a higher name. It does not block.
func (r *Router) SetMembers(members []MeshMember) {
	l := make([]MeshMember, 0, len(members))
	for _, m := range members {
		m.Addr = netip.AddrPortFrom(m.Addr.Addr().Unmap(), m.Addr.Port())
		l = append(l, m)
	}
	r.members.Store(&l)
	r.box.send(membersChanged{})
}

// OnMeshChange sets fn, which gets each up and down change of a member, in order. It runs as a
// hook task. Set it before Run.
func (r *Router) OnMeshChange(fn func(MeshChange)) { r.onMeshChange.Store(&fn) }

// OnMeshSession sets fn, which gets each session that passed Open, after the up change of its
// member. It runs as a hook task. Set it before Run.
func (r *Router) OnMeshSession(fn func(*MeshSession)) { r.onMeshSession.Store(&fn) }

// Up reports whether member name is up: it has an open session.
func (r *Router) Up(name string) bool {
	a, _ := r.ask(name)
	return a.up
}

// Session returns the open session with member name, or nil.
func (r *Router) Session(name string) *MeshSession {
	a, _ := r.ask(name)
	return a.s
}

func (r *Router) ask(name string) (askAnswer, bool) {
	reply := make(chan askAnswer, 1)
	if !r.box.send(askEv{name: name, reply: reply}) {
		return askAnswer{}, false
	}
	return <-reply, true
}

// FetchSnapshot asks each member with an open session, in name order, and returns the first host
// snapshot and the name of its member. With none, the error code is NotFound.
func (r *Router) FetchSnapshot(ctx context.Context) (data []byte, from string, err error) {
	reply := make(chan fetchResult, 1)
	if !r.box.send(fetchEv{reply: reply}) {
		return nil, "", rpc.Errorf(rpc.Unavailable, "relay stopped")
	}
	select {
	case res := <-reply:
		return res.data, res.from, res.err
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
}

// meshConn is one QUIC connection of the mesh, before and after Open.
type meshConn struct {
	qc     *quic.Conn
	conn   *rpc.Conn
	client dpv1.MeshClient
	dialer bool
	opened atomic.Bool // The Open call came, on a connection that this relay accepted.
	// ms is the MS process of the connection. It is set before ready closes.
	ms    atomic.Pointer[msProc]
	ready chan struct{}
}

type meshConnKey struct{}

func newMeshConn(qc *quic.Conn, mux *rpc.Mux, dialer bool) *meshConn {
	conn := rpc.NewConn(qc, mux)
	return &meshConn{qc: qc, conn: conn, client: dpv1.NewMeshClient(conn), dialer: dialer, ready: make(chan struct{})}
}

func (c *meshConn) close(code dpv1.MeshCloseCode, msg string) {
	_ = c.qc.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// serve answers the calls of the other relay until the connection closes or ctx ends.
func (c *meshConn) serve(ctx context.Context) {
	_ = c.conn.Serve(context.WithValue(ctx, meshConnKey{}, c))
	if ctx.Err() != nil {
		c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_RESTART, "relay stops")
	}
}

// session returns the MS of the call of ctx when it is open. A call that comes before the end of
// Open waits for it.
func sessionOf(ctx context.Context) (*msProc, error) {
	c, _ := ctx.Value(meshConnKey{}).(*meshConn)
	if c == nil {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "call is not on a mesh session")
	}
	select {
	case <-c.ready:
		return c.ms.Load(), nil
	case <-ctx.Done():
		return nil, rpc.Errorf(rpc.FailedPrecondition, "mesh session is not open")
	}
}

// serveMesh serves a mesh connection that another relay dialed until it closes or ctx ends. The
// relay keeps it only when the Open call of the other relay passes in time.
func (r *Router) serveMesh(ctx context.Context, qc *quic.Conn) {
	if r.mesh == nil {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(dpv1.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER), "relay has no mesh")
		return
	}
	c := newMeshConn(qc, r.mesh.mux, false)
	t := time.AfterFunc(meshOpenTimeout, func() {
		select {
		case <-c.ready:
		default:
			c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "no Open call")
		}
	})
	defer t.Stop()
	c.serve(ctx)
	c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "")
}

// checkRevision refuses a relay whose revision is below the mesh revision or the minimum of this
// relay.
func (r *Router) checkRevision(v *dpv1.Version) error {
	if got, least := v.GetRevision(), max(r.ver.GetMinRevision(), meshRevision); got < least {
		return fmt.Errorf("relay revision %d is below the minimum %d", got, least)
	}
	return nil
}

// pspSocket returns the data port that a member gave in Open: host, or the address dialed when
// host is empty, at port.
func pspSocket(host string, port uint32, dialed netip.Addr) (netip.AddrPort, error) {
	if port == 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("data port %d is not a port", port)
	}
	if host == "" {
		return netip.AddrPortFrom(dialed.Unmap(), uint16(port)), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("data host %q is not an IP address", host)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
}

// remoteClose returns the code and the reason with which the other relay closed qc. err is the
// error of a call on qc, or nil.
func remoteClose(qc *quic.Conn, err error) (dpv1.MeshCloseCode, string, bool) {
	var ae *quic.ApplicationError
	// quic-go ends the call streams before it sets the close cause.
	if !errors.As(err, &ae) && !errors.As(context.Cause(qc.Context()), &ae) {
		return 0, "", false
	}
	return dpv1.MeshCloseCode(ae.ErrorCode), ae.ErrorMessage, ae.Remote
}

// meshServer serves the Mesh service of a router on mesh connections.
type meshServer struct {
	dpv1.UnimplementedMeshServer
	r *Router
}

// Open answers the first call of a relay that dialed. It checks the certificate, the name and the
// revision of that relay, and its M takes the session.
func (s meshServer) Open(ctx context.Context, req *dpv1.MeshOpenRequest) (*dpv1.MeshOpenResponse, error) {
	c, _ := ctx.Value(meshConnKey{}).(*meshConn)
	if c == nil || c.dialer {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "only the relay that dialed calls Open")
	}
	if !c.opened.CompareAndSwap(false, true) {
		return nil, rpc.Errorf(rpc.FailedPrecondition, "mesh session is already open")
	}
	r, m := s.r, s.r.mesh
	name, from := req.GetName(), addrPort(c.qc.RemoteAddr())
	// The other relay gets msg as the close reason. detail stays in the log.
	refuse := func(code dpv1.MeshCloseCode, status rpc.Code, msg string, detail ...any) error {
		slog.Info("Refused mesh session", append([]any{"relay", name, "remote", from, "reason", msg}, detail...)...)
		c.close(code, msg)
		return rpc.Errorf(status, "%s", msg)
	}
	// The certificate check is first, so that only a relay with a good certificate learns which
	// names are members.
	if err := m.cfg.Verify(c.qc.ConnectionState().TLS.PeerCertificates, name, from); err != nil {
		return nil, refuse(dpv1.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, rpc.PermissionDenied, "relay certificate rejected", "error", err)
	}
	// One session for two relays: only the relay with the lower name dials.
	if name >= m.name {
		return nil, refuse(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, rpc.FailedPrecondition, "the relay with the lower name dials the mesh session")
	}
	if err := r.checkRevision(req.GetVersion()); err != nil {
		return nil, refuse(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE, rpc.FailedPrecondition, err.Error())
	}
	psp, err := pspSocket(req.GetPspHost(), req.GetPspPort(), from.Addr())
	if err != nil {
		return nil, refuse(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, rpc.InvalidArgument, err.Error())
	}
	res := make(chan error, 1)
	if !r.box.send(meshOpened{c: c, open: msOpen{name: name, ref: req.GetRelay(), ver: req.GetVersion(), psp: psp}, res: res}) {
		return nil, refuse(dpv1.MeshCloseCode_MESH_CLOSE_CODE_RESTART, rpc.Unavailable, "relay stops")
	}
	if err := <-res; err != nil {
		code := dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED
		switch {
		case errors.Is(err, errNotMember):
			code = dpv1.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER
		case errors.Is(err, errMeshStopped):
			code = dpv1.MeshCloseCode_MESH_CLOSE_CODE_RESTART
		}
		return nil, refuse(code, rpc.FailedPrecondition, err.Error())
	}
	return r.openResponse(), nil
}

// openResponse returns the answer to Open, and openRequest the call of a dialer.
func (r *Router) openResponse() *dpv1.MeshOpenResponse {
	return &dpv1.MeshOpenResponse{Version: r.ver, Name: r.mesh.name, Relay: r.cfg.Relay, PspPort: uint32(dataPort(r.cfg.Target))}
}

func (r *Router) openRequest() *dpv1.MeshOpenRequest {
	return &dpv1.MeshOpenRequest{Version: r.ver, Name: r.mesh.name, Relay: r.cfg.Relay, PspPort: uint32(dataPort(r.cfg.Target))}
}

var (
	errNotMember   = errors.New("relay is not a member")
	errMeshStopped = errors.New("relay stops")
)

// Presence gives an incoming Presence call of a tenant to the M of the session. The first message
// names the tenant: the project of its VPCs.
func (s meshServer) Presence(ctx context.Context, st presenceServer) error {
	ms, err := sessionOf(ctx)
	if err != nil {
		return err
	}
	first, err := st.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	tenant := first.GetVpcs()
	if len(tenant) == 0 || tenant[0].GetProjectId() == "" {
		return rpc.Errorf(rpc.InvalidArgument, "first Presence message names no VPC of a tenant")
	}
	done := make(chan error, 1)
	if !ms.box.send(msIncoming{st: st, tenant: tenant[0].GetProjectId(), first: first, done: done}) {
		return rpc.Errorf(rpc.Unavailable, "mesh session ended")
	}
	return <-done
}

// TrunkKeys applies the trunk SAs that the calling relay gives for packets to it. The caller is
// the member of the session, never a name in the request.
func (s meshServer) TrunkKeys(ctx context.Context, in *dpv1.KeysRequest) (*dpv1.KeysResponse, error) {
	ms, err := sessionOf(ctx)
	if err != nil {
		return nil, err
	}
	req, err := keyproto.FromProto(in)
	if err != nil {
		return nil, rpc.Errorf(rpc.InvalidArgument, "%v", err)
	}
	for _, sa := range req.SAs {
		// A trunk SA has no VNI. The VNI field of its packets has the sender tag.
		if sa.VNI != 0 {
			return nil, rpc.Errorf(rpc.InvalidArgument, "SA %#x has VNI %#x, and a trunk SA has VNI 0", sa.SPI, sa.VNI)
		}
		if sa.Lane != trunkLane {
			return nil, rpc.Errorf(rpc.InvalidArgument, "SA %#x has lane %d, and a trunk has only lane 0", sa.SPI, sa.Lane)
		}
	}
	res := make(chan callResult, 1)
	if !ms.box.send(msTrunkKeys{req: req, res: res}) {
		return nil, rpc.Errorf(rpc.Unavailable, "mesh session ended")
	}
	select {
	case out := <-res:
		if out.err != nil {
			return nil, out.err
		}
		return out.out.(*dpv1.KeysResponse), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Snapshot sends the snapshot of the host of this relay in parts. The caller is the member of an
// open session, so no other connection gets the bytes.
func (s meshServer) Snapshot(ctx context.Context, _ *dpv1.SnapshotRequest, st rpc.ServerStreamServer[dpv1.SnapshotPart]) error {
	ms, err := sessionOf(ctx)
	if err != nil {
		return err
	}
	var data []byte
	if fn := s.r.mesh.cfg.Snapshot; fn != nil {
		data = fn()
	}
	switch {
	case len(data) == 0:
		return rpc.Errorf(rpc.NotFound, "relay host has no snapshot")
	case len(data) > maxSnapshotSize:
		slog.Warn("Refused to send a snapshot above the size limit", "relay", ms.name, "bytes", len(data), "limit", maxSnapshotSize)
		return rpc.Errorf(rpc.ResourceExhausted, "snapshot of %d bytes is above the limit of %d", len(data), maxSnapshotSize)
	}
	// Only the first part has the size, so that the caller can refuse it before the bytes.
	size := uint64(len(data))
	for rest := data; len(rest) > 0; size = 0 {
		n := min(len(rest), snapshotPartSize)
		if err := st.Send(&dpv1.SnapshotPart{Data: rest[:n], TotalSize: size}); err != nil {
			return err
		}
		rest = rest[n:]
	}
	slog.Info("Sent the host snapshot to a mesh member", "relay", ms.name, "bytes", len(data))
	return nil
}

// fetchSnapshot gets the snapshot of the host of the member on client. The whole call has
// snapshotTimeout, which the member gets in the call header.
func fetchSnapshot(ctx context.Context, client dpv1.MeshClient) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	st, err := client.Snapshot(ctx, &dpv1.SnapshotRequest{})
	if err != nil {
		return nil, err
	}
	var data []byte
	var total uint64
	for first := true; ; first = false {
		part, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if first {
			// The size check comes before the buffer, so a member cannot make this relay hold more.
			if total = part.GetTotalSize(); total > maxSnapshotSize {
				return nil, fmt.Errorf("snapshot size %d is above the limit of %d", total, maxSnapshotSize)
			}
			data = make([]byte, 0, total)
		}
		if uint64(len(data)+len(part.GetData())) > total {
			return nil, fmt.Errorf("snapshot has more bytes than its size of %d", total)
		}
		data = append(data, part.GetData()...)
	}
	if uint64(len(data)) != total || total == 0 {
		return nil, fmt.Errorf("snapshot ended after %d of %d bytes", len(data), total)
	}
	return data, nil
}

// Events of the root for the mesh.
type (
	membersChanged struct{}
	askEv          struct {
		name  string
		reply chan askAnswer
	}
	fetchEv struct{ reply chan fetchResult }
	// meshOpened is a session that a member dialed, whose Open passed the checks. res gets nil
	// when its M took it.
	meshOpened struct {
		c    *meshConn
		open msOpen
		res  chan error
	}
	// fromM is a message of an M to the root.
	fromM struct {
		m   *mChild
		msg any
	}
	mUpChanged struct {
		m    *mChild
		keys []string
	}
	vUpChanged struct{ v *vChild }
)

// syncMembers starts an M for each new member of the list, and ends the M of each member that
// left it or has a new address.
func (r *Router) syncMembers() {
	if r.mesh == nil || r.stopping {
		return
	}
	want := map[string]MeshMember{}
	if l := r.members.Load(); l != nil {
		for _, m := range *l {
			if m.Name != "" && m.Name != r.mesh.name && m.Addr.IsValid() {
				want[m.Name] = m
			}
		}
	}
	for name, c := range r.ms {
		if w, ok := want[name]; ok && w.Addr == c.addr {
			continue
		}
		// A new address is a new relay process, so its old session ends too.
		delete(r.ms, name)
		r.endMember(c, dpv1.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, "relay is not a member at this address", MeshRemoved)
	}
	for name, w := range want {
		if r.ms[name] == nil {
			r.startM(w)
		}
	}
}

// startM starts the M of a member with a trunk port, a cell and a meter, and the announcement
// sets of the VPCs.
func (r *Router) startM(w MeshMember) {
	cell, ok := r.cells.get()
	if !ok {
		slog.Error("No free counter cell for a mesh member", "relay", w.Name)
		return
	}
	meter, ok := r.meters.get()
	if !ok {
		r.cells.put(cell)
		slog.Error("No free meter for a mesh member", "relay", w.Name)
		return
	}
	r.lastPort++
	r.inc++
	ctx, cancel := context.WithCancel(context.Background())
	c := &mChild{
		name: w.Name, addr: w.Addr, inc: r.inc, port: r.lastPort, cell: cell, meter: meter,
		box: newMailbox(0), down: &valueMap{}, up: &valueMap{}, cancel: cancel, parts: map[VPCKey]*recordSet{},
	}
	for key, set := range r.sets {
		store(c.down, setKey(keySet, key), set)
	}
	r.ms[c.name] = c
	r.mall[c] = struct{}{}
	r.trunks[c.port] = c
	watch(ctx, c.up, func(keys []string) { r.box.send(mUpChanged{m: c, keys: keys}) })
	startMember(r, c)
}

// endMember ends the M of c. down is the reason of its down change, or 0 for none.
func (r *Router) endMember(c *mChild, code dpv1.MeshCloseCode, msg string, down MeshDown) {
	if c.ending {
		return
	}
	c.ending = true
	c.box.send(toMEnd{code: code, msg: msg, down: down})
}

// meshOpened gives a session that a member dialed to its M.
func (r *Router) meshOpened(e meshOpened) {
	c := r.ms[e.open.name]
	switch {
	case r.stopping:
		e.res <- errMeshStopped
	case c == nil || c.ending:
		e.res <- fmt.Errorf("%w: %q", errNotMember, e.open.name)
	case !c.box.send(toMConn{c: e.c, open: e.open, res: e.res}):
		e.res <- fmt.Errorf("%w: %q", errNotMember, e.open.name)
	}
}

func (r *Router) fromM(c *mChild, msg any) {
	switch m := msg.(type) {
	case mKeys:
		r.runTrunkKeys(c, m)
	case mTables:
		r.addTables(m.b, false, func(err error) { c.box.send(toTablesDone{err: err}) })
	case mChange:
		c.isUp = m.c.Up
		if !m.c.Up {
			c.s = nil
		}
		if fn := r.onMeshChange.Load(); fn != nil && !r.stopping {
			r.hook(0, func() { (*fn)(m.c) })
		}
	case mSession:
		c.s = m.s
		if id := m.s.relay.GetId(); id != "" {
			c.id = id
		}
		if fn := r.onMeshSession.Load(); fn != nil && !r.stopping {
			r.hook(0, func() { (*fn)(m.s) })
		}
	case mFetched:
		r.fetched(c, m)
	case mEnded:
		c.cancel()
		for key := range c.parts {
			if v := r.vs[key]; v != nil {
				v.down.Delete(viewKey(c))
			}
		}
		delete(r.trunks, c.port)
		delete(r.mall, c)
		if r.ms[c.name] == c {
			delete(r.ms, c.name)
		}
		// The series of a member go on with the M of its new address.
		if n := r.ms[c.name]; n != nil {
			n.base.add(c.base)
			n.base.add(m.final)
			if n.id == "" {
				n.id = c.id
			}
		}
		r.cells.put(c.cell)
		r.meters.put(c.meter)
	}
}

// runTrunkKeys runs a key operation of an M on its trunk port, adds its keys entries to the
// pending batch and answers it after their write.
func (r *Router) runTrunkKeys(c *mChild, m mKeys) {
	done := toKeysDone{port: c.port, op: m.op}
	now := time.Now()
	var b batch
	switch m.op {
	case opOffer:
		b, done.offer, done.err = r.keys.trunkOffer(c.port, m.session, now)
	case opRefused:
		b, done.offer, done.err = r.keys.trunkRefused(c.port, m.session, m.spis, now)
	case opApply:
		b, done.refused, done.err = r.keys.trunkApply(c.port, m.session, m.req, now)
	case opClose:
		var err error
		if b, err = r.keys.close(c.port); err != nil {
			slog.Warn("Failed to delete the keys entries of a trunk", "relay", c.name, "error", err)
		}
	}
	r.addTables(b, false, func(err error) {
		switch {
		case err == nil:
		case m.op == opClose:
			slog.Warn("Failed to delete the keys entries of a trunk", "relay", c.name, "error", err)
		case done.err == nil:
			done.err = rpc.Errorf(rpc.Unavailable, "failed to write keys entries: %v", err)
		}
		if m.op == opApply {
			done.tx = r.keys.hasTx(c.port)
		}
		c.box.send(done)
	})
}

// viewKey is the key of the member values and part of c in the map of a V.
func viewKey(c *mChild) string { return keyMember + strconv.FormatUint(c.inc, 10) }

// keyVPC returns the VPC of a map key with prefix.
func keyVPC(prefix, k string) (VPCKey, bool) {
	project, uid, ok := strings.Cut(strings.TrimPrefix(k, prefix), "/")
	return VPCKey{Project: project, UID: uid}, ok && strings.HasPrefix(k, prefix)
}

// memberChanged gives each V the new member values and its new part of the VPC of the V.
func (r *Router) memberChanged(c *mChild, keys []string) {
	if _, ok := r.mall[c]; !ok {
		return
	}
	for _, k := range keys {
		switch {
		case k == keyValues:
			c.values = load[*memberValues](c.up, keyValues)
			for key := range c.parts {
				r.storeView(c, key)
			}
		case strings.HasPrefix(k, keyPart):
			key, ok := keyVPC(keyPart, k)
			if !ok {
				continue
			}
			if rs := load[*recordSet](c.up, k); rs != nil {
				c.parts[key] = rs
			} else {
				delete(c.parts, key)
			}
			r.storeView(c, key)
		}
	}
}

// storeView stores the values and the part of c for the V of key.
func (r *Router) storeView(c *mChild, key VPCKey) {
	v := r.vs[key]
	if v == nil {
		return
	}
	part := c.parts[key]
	if part == nil {
		v.down.Delete(viewKey(c))
		return
	}
	store(v.down, viewKey(c), &memberView{inc: c.inc, values: c.values, part: part})
}

// publishSet gives the announcement set of the V of key to each M. A nil set deletes it.
func (r *Router) publishSet(key VPCKey, set *annSet) {
	if r.mesh == nil {
		return
	}
	k := setKey(keySet, key)
	if set == nil {
		delete(r.sets, key)
	} else if r.sets[key] == set {
		return
	} else {
		r.sets[key] = set
	}
	for c := range r.mall {
		if set == nil {
			c.down.Delete(k)
		} else {
			store(c.down, k, set)
		}
	}
}

// startFetch asks the members with an open session for the host snapshot, in name order.
func (r *Router) startFetch(reply chan fetchResult) {
	var names []string
	for name, c := range r.ms {
		if c.isUp && !c.ending {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	r.fetchN++
	r.fetches[r.fetchN] = &fetchRun{reply: reply, names: names}
	r.nextFetch(r.fetchN)
}

// nextFetch asks the next member of the run n, or answers that no member has a snapshot.
func (r *Router) nextFetch(n uint64) {
	run := r.fetches[n]
	for len(run.names) > 0 {
		if c := r.ms[run.names[0]]; c != nil && !c.ending && c.box.send(toFetch{n: n}) {
			return
		}
		run.names = run.names[1:]
	}
	delete(r.fetches, n)
	run.reply <- fetchResult{err: rpc.Errorf(rpc.NotFound, "no mesh member has a snapshot")}
}

func (r *Router) fetched(c *mChild, m mFetched) {
	run := r.fetches[m.n]
	if run == nil {
		return
	}
	if m.err == nil {
		delete(r.fetches, m.n)
		run.reply <- fetchResult{data: m.data, from: c.name}
		return
	}
	slog.Debug("Failed to fetch the snapshot of a mesh member", "relay", c.name, "error", m.err)
	if len(run.names) > 0 && run.names[0] == c.name {
		run.names = run.names[1:]
	}
	r.nextFetch(m.n)
}

// alternates returns the relays that an agent of this relay can move to: each member with an
// open session whose Open gave agent addresses, in name order, as Mesh.Alternates did.
func (r *Router) alternates() []*dpv1.RelayRef {
	names := make([]string, 0, len(r.ms))
	for name, c := range r.ms {
		if c.isUp && c.s != nil && len(c.s.relay.GetAddresses()) > 0 {
			names = append(names, name)
		}
	}
	// The mesh has no measure of distance, so the order is the same each time.
	slices.Sort(names)
	var out []*dpv1.RelayRef
	for _, name := range names {
		ref := r.ms[name].s.relay
		// Relays behind one name give the same ID and the same addresses.
		if !slices.ContainsFunc(out, func(o *dpv1.RelayRef) bool { return proto.Equal(o, ref) }) {
			out = append(out, ref)
		}
	}
	return out
}
