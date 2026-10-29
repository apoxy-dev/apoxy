// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// dialed is a relay connection after the handshake and the Session call up to
// Config. The session that takes it owns it.
type dialed struct {
	ep     endpoint
	name   string         // TLS name of the relay.
	roots  *x509.CertPool // Check relay certs. Nil means the system roots.
	qc     *quic.Conn
	client dp.RelayClient
	st     rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]
	ctx    context.Context // The context of st. cancel ends the call.
	cancel context.CancelFunc

	relayAddr netip.AddrPort // Where PSP packets, path probes and lane keep-alives go. See pspAddr.
	maxLanes  uint32         // Most lane ports that the relay takes.
	version   *dp.Version    // Version of the relay, from Welcome.
	relayID   string         // ID of the relay, from Welcome.
	config    *dp.Config     // The first Config.
	begin     time.Time      // Start of the dial.
	connect   time.Duration  // From the start of the dial to the first Config.

	stats    func() quic.ConnectionStats // Stats of qc. A zero MinRTT is not known.
	helloRTT time.Duration               // From the send of Hello to Welcome.
}

// close closes the connection of d in its own goroutine and ends its call.
func (d *dialed) close(reason string) {
	d.cancel()
	go func() { _ = d.qc.CloseWithError(0, reason) }()
}

// choiceRTT returns the round-trip time of d for the choice: the lower known
// time of the lowest QUIC time and the time from Hello to Welcome. After a late
// start of the path, QUIC can have no sample of the Hello exchange at the choice.
func (d *dialed) choiceRTT() time.Duration {
	low := d.stats().MinRTT
	if low <= 0 || d.helloRTT > 0 && d.helloRTT < low {
		return d.helloRTT
	}
	return low
}

// dial runs the handshake with the relay at e and the Session call up to
// Config. ctx ends the dial; the Session call of the result lives until its cancel.
func (a *Agent) dial(ctx context.Context, e endpoint, roots *x509.CertPool) (*dialed, error) {
	host, _, err := net.SplitHostPort(e.addr)
	if err != nil {
		return nil, err
	}
	ua, err := net.ResolveUDPAddr("udp", e.addr)
	if err != nil {
		return nil, err
	}
	d := &dialed{ep: e, name: cmp.Or(e.id, host), roots: roots, begin: time.Now()}
	dctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	qc, err := a.cfg.Transport.Dial(dctx, ua, &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              roots,
		ServerName:           d.name,
		NextProtos:           []string{dp.ALPNRelay},
		GetClientCertificate: a.cfg.Identity.GetClientCertificate,
	}, a.quicCfg)
	if err != nil {
		return nil, err
	}
	a.quicLost.add(qc)
	d.qc, d.stats = qc, qc.ConnectionStats
	d.client = dp.NewRelayClient(rpc.NewConn(qc, nil))
	// The call lives after the dial, under the context of the caller.
	d.ctx, d.cancel = context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, d.cancel)
	// A relay that does not answer in time ends the dial.
	late := context.AfterFunc(dctx, func() { _ = qc.CloseWithError(0, "relay session did not open in time") })
	err = a.hello(d)
	late()
	stop()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		if cause := context.Cause(qc.Context()); cause != nil {
			err = fmt.Errorf("%w (connection: %w)", err, cause)
		}
		d.close("")
		return nil, relayUpgrade(e.addr, err)
	}
	return d, nil
}

// hello runs the Session call of d up to Config.
func (a *Agent) hello(d *dialed) error {
	st, err := d.client.Session(d.ctx)
	if err != nil {
		return err
	}
	d.st = st
	sent := time.Now()
	if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{
		// The agent asks for PSP mode, with no fallback reason. The relay only counts them.
		Mode: dp.Mode_MODE_PSP, Version: a.ver, Name: a.cfg.Name,
		// The relay tells two processes with one identity and one name apart by the instance.
		Instance:        a.instance,
		LocalRoutesOnly: a.cfg.LocalRoutesOnly,
	}}}); err != nil {
		return err
	}
	m, err := st.Recv()
	if err != nil {
		return err
	}
	d.helloRTT = time.Since(sent)
	w := m.GetWelcome()
	if w == nil {
		return fmt.Errorf("relay sent %T before Welcome", m.GetMsg())
	}
	if d.relayAddr, err = pspAddr(w, d.qc.RemoteAddr().(*net.UDPAddr).AddrPort().Addr()); err != nil {
		return err
	}
	d.maxLanes = w.GetMaxLanes()
	d.version = w.GetVersion()
	// The dial fails for a relay that is too old, so the agent dials the next relay.
	if err := relayRevision(d.version, a.ver); err != nil {
		return err
	}
	// The connection has the key of its relay from the Welcome.
	if d.relayID = w.GetRelayId(); d.relayID == "" {
		return errors.New("relay sent no relay ID")
	}
	if m, err = st.Recv(); err != nil {
		return err
	}
	cfg := m.GetConfig()
	if cfg == nil {
		return fmt.Errorf("relay sent %T before Config", m.GetMsg())
	}
	d.connect = time.Since(d.begin)
	if err := st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Status{Status: &dp.Status{ConnectTime: durationpb.New(d.connect)}}}); err != nil {
		return err
	}
	d.config = cfg
	return nil
}
