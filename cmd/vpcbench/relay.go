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
)

// relaySockBuf is the socket buffer size of the relay socket, as in the relay.
const relaySockBuf = 16 << 20

// runRelay serves relay sessions of one VPC with the vpctest fakes until ctx
// ends or a client sends stop. The CA signs the relay cert and the agent
// certs; the control port gives it to the server and the client.
func runRelay(ctx context.Context, o options, ready func(netip.AddrPort)) error {
	start := time.Now()
	ca, err := vpctest.NewCA()
	if err != nil {
		return err
	}
	cert, err := ca.RelayCert(relayID)
	if err != nil {
		return err
	}
	ua, err := net.ResolveUDPAddr("udp", o.Listen)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	defer uc.Close()
	if err := errors.Join(uc.SetReadBuffer(relaySockBuf), uc.SetWriteBuffer(relaySockBuf)); err != nil {
		slog.Warn("Failed to set the relay socket buffers", "bytes", relaySockBuf, "error", err)
	}
	addr := uc.LocalAddr().(*net.UDPAddr).AddrPort()
	slog.Info("Relay socket is ready", "address", addr, "rcvbuf", sockRcvbuf(uc))

	// A driver can stop the link when it gets the XDP program, and the host can then
	// take the address off for a short time. So the control port opens first.
	cl, err := net.Listen("tcp", addr.String())
	if err != nil {
		return err
	}
	defer cl.Close()

	r := relay.NewRouter(vpctest.NewTrust(ca), relay.Config{LaneSources: o.Lanes})
	xdpCPU := func() float64 { return 0 }
	var xdpMode string
	if o.XDP != "" {
		x, mode, err := r.StartXDP(relay.XDPConfig{Port: addr.Port(), Iface: o.XDP, Generic: o.XDPMode != "driver"})
		if err != nil {
			return err
		}
		defer x.Close()
		slog.Info("Relay forwards PSP packets in XDP", "iface", o.XDP, "mode", mode)
		sec, stop, err := xdpSeconds(o.XDP)
		if err != nil {
			return fmt.Errorf("read the XDP run time: %w", err)
		}
		defer stop()
		xdpCPU, xdpMode = sec, mode
	}
	// The kernel joins the datagrams of a socket with UDP GRO before generic
	// XDP runs, so the relay socket has no GRO with XDP in generic mode.
	tr := &quic.Transport{Conn: uc, EnableGRO: xdpMode != "generic"}
	defer tr.Close()
	tr.NonQUICPacketHandler, tr.NonQUICBatchEnd = r.PacketHandler(ctx, tr)
	ln, err := tr.Listen(r.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*cert}}), tunnel.RelayQUICConfig())
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &relay.Server{
		R:         r,
		Networks:  vpctest.Networks{Project: project, VPC: vpcName, Net: relay.Network{ID: vni, MTU: uint32(o.MTU)}},
		Addresses: &vpctest.Addresses{},
		Cert:      func() (*tls.Certificate, error) { return cert, nil },
		RelayID:   relayID,
	}

	caPEM := encodeCA(ca)
	if ready != nil {
		ready(addr)
	}
	slog.Info("Serving relay sessions", "address", addr)

	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Go(func() { r.Run(ctx) })
	wg.Go(func() {
		serveMarks(ctx, cl, func(req request) (reply, error) {
			switch req.Op {
			case "ca":
				return reply{CA: caPEM}, nil
			case "mark":
				drops, reasons, xdp, passed := relayCounters(r)
				xdpS := xdpCPU()
				m := mark{
					Nanos: time.Since(start).Nanoseconds(), CPU: bench.CPUSeconds() + xdpS, HostCPU: bench.HostCPUSeconds(),
					Drops: drops, DropReasons: reasons, SockDrops: sockDrops(uc),
					XDPPackets: xdp, XDPPassed: passed, XDPSeconds: xdpS, XDPMode: xdpMode,
					Sends: r.ForwardStats(), CPUs: bench.PerCPU(),
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

// serveMarks answers the control connections of ln until ctx ends.
func serveMarks(ctx context.Context, ln net.Listener, handle func(request) (reply, error)) {
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
			if err := serveCtl(c, handle); err != nil && ctx.Err() == nil {
				slog.Warn("Control connection failed", "remote", c.RemoteAddr(), "error", err)
			}
		})
	}
}

// relayCounters returns the sum of the drop counters of r and the drops by
// reason, the packets that its XDP program forwarded, and the packets that it
// gave to the socket path, by result. The maps have only the counters that are not 0.
func relayCounters(r *relay.Router) (drops uint64, reasons map[string]uint64, xdp uint64, passed map[string]uint64) {
	ch := make(chan prometheus.Metric, 8)
	go func() {
		r.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var d dto.Metric
		if m.Write(&d) != nil {
			continue
		}
		n := uint64(d.GetCounter().GetValue())
		switch desc := m.Desc().String(); {
		case strings.Contains(desc, `"apoxy_vpc_relay_dropped_packets_total"`):
			drops += n
			if n > 0 {
				if reasons == nil {
					reasons = map[string]uint64{}
				}
				reasons[label(&d, "reason")] += n
			}
		case !strings.Contains(desc, `"apoxy_vpc_relay_xdp_packets_total"`):
		case label(&d, "result") == "forwarded":
			xdp += n
		case n > 0:
			if passed == nil {
				passed = map[string]uint64{}
			}
			passed[label(&d, "result")] += n
		}
	}
	return drops, reasons, xdp, passed
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
