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

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
	relaydp "github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// runRelay serves relay sessions of one VPC with the vpctest fakes until ctx
// ends or a client sends stop. The CA signs the relay cert and the agent
// certs; the control port at -listen gives it and the QUIC address of the
// relay to the server and the client. The data plane and QUIC of the relay
// run on the relay device of -iface or -imds. ready gets the control address.
func runRelay(ctx context.Context, o options, ready func(netip.AddrPort)) error {
	start := time.Now()
	cfg, err := relayConfig(o)
	if err != nil {
		return err
	}
	ifc, err := relaydp.FindInterface(ctx, cfg)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	d, err := relaydp.OpenDevice(ifc)
	if err != nil {
		return err
	}
	wg.Go(func() {
		if err := d.Run(ctx); err != nil {
			cancel(fmt.Errorf("relay device: %w", err))
		}
	})
	quicAddr := d.PacketConn().LocalAddr().(*net.UDPAddr).AddrPort()
	slog.Info("Relay device is open", "link", ifc.Name, "own", ifc.Own, "quic_address", quicAddr)

	ca, err := vpctest.NewCA()
	if err != nil {
		return err
	}
	cert, err := ca.RelayCert(relayID)
	if err != nil {
		return err
	}
	cl, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return err
	}
	defer cl.Close()
	addr := cl.Addr().(*net.TCPAddr).AddrPort()

	r, err := relay.NewRouter(relay.Config{
		Relay:       &dp.RelayRef{Id: relayID, Addresses: []string{quicAddr.String()}},
		Trust:       vpctest.NewTrust(ca),
		Addresses:   &addresses{},
		Target:      d.Target(),
		LaneSources: o.Lanes,
	})
	if err != nil {
		return err
	}
	r.AddTenant(project)
	r.AddVPC(relay.VPCKey{Project: project, UID: vpcName}, relay.Network{ID: vni, MTU: uint32(o.MTU)})
	tr := &quic.Transport{Conn: d.PacketConn()}
	defer tr.Close()
	quicConf := tunnel.RelayQUICConfig()
	quicConf.KeepAlivePeriod = relay.AgentKeepAlive
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
	slog.Info("Serving relay sessions", "control_address", addr, "quic_address", quicAddr)

	wg.Go(func() { _ = r.Run(ctx) })
	wg.Go(func() {
		serveMarks(ctx, cl, func(_ net.Addr, req request) (reply, error) {
			// A relay that stops gives no CA: the process of the next run has a new one.
			if ctx.Err() != nil && req.Op == "ca" {
				return reply{}, errors.New("the relay stops")
			}
			switch req.Op {
			case "ca":
				return reply{CA: caPEM, Addr: quicAddr.String()}, nil
			case "mark":
				drops, reasons := relayDrops(r)
				m := mark{
					Nanos: time.Since(start).Nanoseconds(), CPU: bench.CPUSeconds(), HostCPU: bench.HostCPUSeconds(),
					KickCPU: bench.ThreadCPUSeconds(relaydp.KickThread),
					Drops:   drops, DropReasons: reasons, CPUs: bench.PerCPU(),
				}
				o.marked(req.Index, req.Window)
				return reply{Mark: m}, nil
			case "stop":
				slog.Info("A client stopped the relay")
				cancel(nil)
				return reply{}, nil
			}
			return reply{}, fmt.Errorf("unknown op %q", req.Op)
		})
	})
	err = srv.Serve(ctx, ln)
	if cause := context.Cause(ctx); cause != nil {
		if errors.Is(cause, context.Canceled) {
			return nil
		}
		return cause
	}
	return err
}

// relayConfig returns the relay interface config of the flags. With -imds the relay finds its link
// in IMDSv2. With -iface the config has the MAC of the link and its addresses that are not
// link-local, as the kernel has them.
func relayConfig(o options) (*configv1alpha1.RelayInterface, error) {
	if o.IMDS {
		return &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS, ZeroCopy: o.ZeroCopy}, nil
	}
	link, err := net.InterfaceByName(o.Iface)
	if err != nil {
		return nil, fmt.Errorf("failed to find the relay link: %w", err)
	}
	addrs, err := link.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to read the addresses of %s: %w", o.Iface, err)
	}
	cfg := &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceStatic, MAC: link.HardwareAddr.String(), ZeroCopy: o.ZeroCopy}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok || ip.Unmap().IsLinkLocalUnicast() {
			continue
		}
		bits, _ := ipn.Mask.Size()
		cfg.Addresses = append(cfg.Addresses, netip.PrefixFrom(ip.Unmap(), bits).String())
	}
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("the relay link %s has no address", o.Iface)
	}
	return cfg, nil
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
