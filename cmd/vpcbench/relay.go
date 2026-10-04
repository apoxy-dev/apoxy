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
	"os"
	"path/filepath"
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

// caFile is the name of the CA file in the work dir. It has the CA cert and
// its key, and it signs the relay cert and the agent certs.
const caFile = "vpcbench-ca.pem"

// relaySockBuf is the socket buffer size of the relay socket, as in the relay.
const relaySockBuf = 16 << 20

// runRelay serves relay sessions of one VPC with the vpctest fakes until ctx
// ends. It writes the CA file before it opens the control port.
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

	r := relay.NewRouter(vpctest.NewTrust(ca), relay.Config{})
	// The relay socket has no XDP program, so GRO is safe.
	tr := &quic.Transport{Conn: uc, EnableGRO: true}
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

	if err := writeCA(o.WorkDir, ca); err != nil {
		return err
	}
	cl, err := net.Listen("tcp", addr.String())
	if err != nil {
		return err
	}
	defer cl.Close()
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
			if req.Op != "mark" {
				return reply{}, fmt.Errorf("unknown op %q", req.Op)
			}
			return reply{Mark: mark{
				Nanos: time.Since(start).Nanoseconds(), CPU: bench.CPUSeconds(), Drops: relayDrops(r), SockDrops: sockDrops(uc),
			}}, nil
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

// relayDrops returns the sum of the drop counters of r.
func relayDrops(r *relay.Router) uint64 {
	ch := make(chan prometheus.Metric, 8)
	go func() {
		r.Collect(ch)
		close(ch)
	}()
	var n uint64
	for m := range ch {
		var d dto.Metric
		if m.Write(&d) == nil {
			n += uint64(d.GetCounter().GetValue())
		}
	}
	return n
}

// writeCA writes the CA cert and key to the CA file in dir. The rename makes
// the change in one step.
func writeCA(dir string, ca *vpctest.CA) error {
	key, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	b = append(b, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key})...)
	f, err := os.CreateTemp(dir, caFile+".*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, caFile))
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("write the CA file: %w", err)
	}
	return nil
}

// loadCA reads the CA file in dir.
func loadCA(dir string) (*vpctest.CA, error) {
	path := filepath.Join(dir, caFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ca := &vpctest.CA{}
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
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if ca.Cert == nil || ca.Key == nil {
		return nil, fmt.Errorf("%s has no CA cert and key", path)
	}
	return ca, nil
}
