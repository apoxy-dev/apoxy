// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// relaySockBuf is the socket buffer size of the PSP socket, as in the relay.
const relaySockBuf = 16 << 20

// runRelay serves relay sessions of one VPC with the vpctest fakes until ctx
// ends or a client sends stop. The CA signs the relay cert and the agent
// certs; the control port gives it to the server and the client. The data
// plane of the relay runs on the PSP socket.
func runRelay(ctx context.Context, o options, ready func(netip.AddrPort)) error {
	start := time.Now()
	uc, err := listenUDP(o.Listen)
	if err != nil {
		return err
	}
	defer uc.Close()
	addr := uc.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, err := listenPSP(o, addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	pspAddr := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	slog.Info("Relay sockets are ready", "address", addr, "psp_address", pspAddr, "rcvbuf", sockRcvbuf(pc))

	ca, err := vpctest.NewCA()
	if err != nil {
		return err
	}
	cert, err := ca.RelayCert(relayID)
	if err != nil {
		return err
	}
	cl, err := net.Listen("tcp", addr.String())
	if err != nil {
		return err
	}
	defer cl.Close()

	plane := vpctest.NewSockets(pc, uc)
	go func() { _ = plane.Run() }()
	r, err := relay.NewRouter(relay.Config{
		Relay:       &dp.RelayRef{Id: relayID, Addresses: []string{addr.String()}},
		Trust:       vpctest.NewTrust(ca),
		Addresses:   &addresses{},
		Target:      plane.Target,
		LaneSources: o.Lanes,
	})
	if err != nil {
		return err
	}
	r.AddTenant(project)
	r.AddVPC(relay.VPCKey{Project: project, UID: vpcName}, relay.Network{ID: vni, MTU: uint32(o.MTU)})
	tr := &quic.Transport{Conn: uc, ConnContext: relay.TraceContext}
	defer tr.Close()
	quicConf := tunnel.RelayQUICConfig()
	quicConf.Tracer, quicConf.KeepAlivePeriod = relay.TraceRTT, relay.AgentKeepAlive
	ln, err := tr.Listen(r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}), quicConf)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &relay.Server{R: r}

	caPEM := encodeCA(ca)
	if ready != nil {
		ready(addr)
	}
	slog.Info("Serving relay sessions", "address", addr)

	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Go(func() { _ = r.Run(ctx) })
	wg.Go(func() {
		serveMarks(ctx, cl, func(_ net.Addr, req request) (reply, error) {
			// A relay that stops gives no CA: the process of the next run has a new one.
			if ctx.Err() != nil && req.Op == "ca" {
				return reply{}, errors.New("the relay stops")
			}
			switch req.Op {
			case "ca":
				return reply{CA: caPEM}, nil
			case "mark":
				drops, reasons := relayDrops(r)
				m := mark{
					Nanos: time.Since(start).Nanoseconds(), CPU: bench.CPUSeconds(), HostCPU: bench.HostCPUSeconds(),
					Drops: drops, DropReasons: reasons, SockDrops: sockDrops(pc), CPUs: bench.PerCPU(),
				}
				o.marked(req.Index, req.Window)
				return reply{Mark: m}, nil
			case "stop":
				slog.Info("A client stopped the relay")
				cancel()
				return reply{}, nil
			}
			return reply{}, fmt.Errorf("unknown op %q", req.Op)
		})
	})
	err = srv.Serve(ctx, ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// defaultPSPPort is the PSP port of a relay with no -psp-listen.
const defaultPSPPort = 1000

// listenPSP opens the PSP socket of the relay: at -psp-listen, or at the IP
// address of the QUIC socket with the default PSP port.
func listenPSP(o options, quicAddr netip.AddrPort) (*net.UDPConn, error) {
	addr := o.PSPListen
	if addr == "" {
		addr = netip.AddrPortFrom(quicAddr.Addr(), defaultPSPPort).String()
	}
	pc, err := listenUDP(addr)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(pc.SetReadBuffer(relaySockBuf), pc.SetWriteBuffer(relaySockBuf)); err != nil {
		slog.Warn("Failed to set the PSP socket buffers", "bytes", relaySockBuf, "error", err)
	}
	return pc, nil
}

// listenUDP opens the UDP socket of a relay at addr.
func listenUDP(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", ua)
}

// ctlRetry is the time between two tries of a control call.
const ctlRetry = 200 * time.Millisecond

// addresses is a relay.Addresses that gives each attachment the next /96 of the
// VPC network.
type addresses struct {
	mu   sync.Mutex
	next int
}

var _ relay.Addresses = (*addresses)(nil)

func (a *addresses) Assign(context.Context, *relay.Attachment, func()) ([]netip.Prefix, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next >= 0xffff {
		return nil, errors.New("address pool is full")
	}
	a.next++
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd61:706f:7879:12:3400:%x::/96", a.next))}, nil
}

func (a *addresses) Attached(*relay.Attachment) {}

func (a *addresses) Release(*relay.Attachment) {}

// serveMarks answers the control connections of ln until ctx ends. handle gets
// the remote address of the connection of each request.
func serveMarks(ctx context.Context, ln net.Listener, handle func(net.Addr, request) (reply, error)) {
	var wg sync.WaitGroup
	defer wg.Wait()
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Go(func() {
			defer c.Close()
			defer context.AfterFunc(ctx, func() { _ = c.Close() })()
			err := serveCtl(c, func(req request) (reply, error) { return handle(c.RemoteAddr(), req) })
			if err != nil && ctx.Err() == nil {
				slog.Warn("Control connection failed", "remote", c.RemoteAddr(), "error", err)
			}
		})
	}
}

// relayDrops returns the sum of the drop counters of the data plane of r and the
// drops by reason. The map has only the counters that are not 0.
func relayDrops(r *relay.Router) (drops uint64, reasons map[string]uint64) {
	ch := make(chan prometheus.Metric, 8)
	go func() {
		r.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var d dto.Metric
		if m.Write(&d) != nil || !strings.Contains(m.Desc().String(), `"apoxy_vpc_relay_dropped_packets_total"`) {
			continue
		}
		n := uint64(d.GetCounter().GetValue())
		drops += n
		if n > 0 {
			if reasons == nil {
				reasons = map[string]uint64{}
			}
			reasons[label(&d, "reason")] += n
		}
	}
	return drops, reasons
}

// label returns the value of the label name of a counter.
func label(d *dto.Metric, name string) string {
	for _, l := range d.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// encodeCA returns the CA cert and key in PEM.
func encodeCA(ca *vpctest.CA) []byte {
	key, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return nil
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	return append(b, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key})...)
}

// decodeCA reads the CA cert and key from PEM.
func decodeCA(b []byte) (*vpctest.CA, error) {
	ca := &vpctest.CA{}
	var err error
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			ca.Cert, err = x509.ParseCertificate(blk.Bytes)
		case "EC PRIVATE KEY":
			ca.Key, err = x509.ParseECPrivateKey(blk.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parse the CA: %w", err)
		}
	}
	if ca.Cert == nil || ca.Key == nil {
		return nil, errors.New("the relay sent no CA cert and key")
	}
	return ca, nil
}
