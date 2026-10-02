package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"golang.org/x/net/ipv4"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
)

// Socket paths. Each QUIC path gives quic-go a net.PacketConn on one UDP socket.
const (
	// pathRaw gives quic-go the *net.UDPConn.
	pathRaw = "raw"
	// pathWrapped builds the conn as the relay and the agent do today: batchpc
	// and bifurcate on both sides, and conntrackpc on the client.
	pathWrapped = "wrapped"
	// pathOOB uses the prototype demux (see demux.go).
	pathOOB = "oob"
	// pathUDP sends plain UDP with no QUIC. It is the upper limit.
	pathUDP = "udp"
)

const alpn = "sockbench"

// udpBatch is the number of messages in one sendmmsg or recvmmsg call.
const udpBatch = 64

// quicOverhead is what quic-go adds to one datagram in a short header packet:
// 1+4+2 B header, 1+2 B frame header and a 16 B tag. The udp path adds it to
// each packet, so the packets have the same size on the wire.
const quicOverhead = 26

// quicConfig has the values of the tunnel QUIC config (pkg/tunnel/quic.go).
func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                true,
		DisableCongestionControl:       true,
		InitialPacketSize:              1350,
		InitialConnectionReceiveWindow: 5 * 1000 * 1000,
		MaxConnectionReceiveWindow:     100 * 1000 * 1000,
		KeepAlivePeriod:                5 * time.Second,
		MaxIdleTimeout:                 15 * time.Second,
	}
}

func listenUDP(addr string, sockbuf int) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	if sockbuf > 0 {
		if err := uc.SetReadBuffer(sockbuf); err != nil {
			slog.Warn("Failed to set UDP receive buffer", "error", err)
		}
		if err := uc.SetWriteBuffer(sockbuf); err != nil {
			slog.Warn("Failed to set UDP send buffer", "error", err)
		}
	}
	return uc, nil
}

// quicConn returns the conn that quic-go gets on path. remote is the server on
// the client side and nil on the server side. The close func closes uc too.
func quicConn(path string, uc *net.UDPConn, remote *net.UDPAddr) (net.PacketConn, func(), error) {
	switch path {
	case pathRaw:
		return uc, func() { uc.Close() }, nil
	case pathWrapped:
		// The same layers as pkg/cmd/alpha/tunnel_relay.go and agent.newPacketPlaneAt.
		bpc, err := batchpc.New("udp", uc)
		if err != nil {
			uc.Close()
			return nil, nil, err
		}
		geneve, pcQuic := bifurcate.Bifurcate(bpc)
		if remote == nil {
			return pcQuic, func() { pcQuic.Close(); geneve.Close() }, nil
		}
		mux := conntrackpc.New(pcQuic, conntrackpc.Options{})
		vpc, err := mux.Open(remote)
		if err != nil {
			mux.Close()
			return nil, nil, err
		}
		return vpc, func() { vpc.Close(); mux.Close(); geneve.Close() }, nil
	case pathOOB:
		d := newDemux(uc)
		if remote == nil {
			return d.Any(), func() { d.Close() }, nil
		}
		return d.Open(remote.AddrPort()), func() { d.Close() }, nil
	default:
		uc.Close()
		return nil, nil, fmt.Errorf("path %q has no QUIC conn", path)
	}
}

// listenQUIC listens on uc as the relay does (quic.ListenEarly). It counts
// the packets that quic-go drops in drops.
func listenQUIC(path string, uc *net.UDPConn, drops *atomic.Uint64) (*quic.EarlyListener, func(), error) {
	pc, closePC, err := quicConn(path, uc, nil)
	if err != nil {
		return nil, nil, err
	}
	_, cert, err := cryptoutils.GenerateSelfSignedTLSCert(alpn)
	if err != nil {
		closePC()
		return nil, nil, err
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}
	cfg := quicConfig()
	cfg.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
		return &logging.ConnectionTracer{
			DroppedPacket: func(logging.PacketType, logging.PacketNumber, logging.ByteCount, logging.PacketDropReason) {
				drops.Add(1)
			},
		}
	}
	ln, err := quic.ListenEarly(pc, tlsConf, cfg)
	if err != nil {
		closePC()
		return nil, nil, fmt.Errorf("listen QUIC: %w", err)
	}
	return ln, func() { closePC(); ln.Close() }, nil
}

// dialQUIC dials n connections from one quic.Transport on uc, as the agent
// API client does.
func dialQUIC(ctx context.Context, path string, uc *net.UDPConn, raddr *net.UDPAddr, n int) ([]quic.Connection, func(), error) {
	pc, closePC, err := quicConn(path, uc, raddr)
	if err != nil {
		return nil, nil, err
	}
	tr := &quic.Transport{Conn: pc}
	var conns []quic.Connection
	// Close the conn before the Transport, so that its read loop ends.
	closeAll := func() {
		for _, c := range conns {
			_ = c.CloseWithError(0, "")
		}
		closePC()
		_ = tr.Close()
	}
	// The server uses a self-signed certificate.
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}} //nolint:gosec
	for range n {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		c, err := tr.Dial(dctx, raddr, tlsConf, quicConfig())
		cancel()
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("dial QUIC: %w", err)
		}
		conns = append(conns, c)
	}
	return conns, closeAll, nil
}

// acceptDatagrams counts the datagrams of every connection on ln.
func acceptDatagrams(ctx context.Context, ln *quic.EarlyListener, received *atomic.Uint64) {
	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		go func() {
			select {
			case <-c.HandshakeComplete():
			case <-ctx.Done():
				return
			}
			slog.Info("Accepted connection", "remote", c.RemoteAddr(), "gso_active", c.ConnectionState().GSO)
			for {
				b, err := c.ReceiveDatagram(ctx)
				if err != nil {
					return
				}
				quic.ReleaseDatagram(b)
				received.Add(1)
			}
		}()
	}
}

// sendDatagrams sends datagrams on c as fast as quic-go takes them. Before
// warmEnd, path MTU discovery can still raise the limit. It runs only while
// the connection sends, so a datagram that is too large is sent smaller.
func sendDatagrams(ctx context.Context, c quic.Connection, size int, warmEnd time.Time, sent *atomic.Uint64) error {
	p := make([]byte, size)
	for ctx.Err() == nil {
		err := c.SendDatagram(p)
		var tooLarge *quic.DatagramTooLargeError
		switch {
		case err == nil:
			sent.Add(1)
		case ctx.Err() != nil:
			return nil
		case errors.As(err, &tooLarge) && time.Now().Before(warmEnd):
			_ = c.SendDatagram(p[:min(size, int(tooLarge.MaxDatagramPayloadSize))])
		default:
			return fmt.Errorf("send datagram: %w", err)
		}
	}
	return nil
}

// blastUDP sends UDP packets of size+quicOverhead bytes to dst with GSO, or
// with sendmmsg when gso is false.
func blastUDP(ctx context.Context, uc *net.UDPConn, dst *net.UDPAddr, size int, gso bool, sent *atomic.Uint64) error {
	n := size + quicOverhead
	if gso {
		segs := max(1, min(maxGSOSegments, 64000/n))
		oob, err := gsoControl(n)
		if err != nil {
			return err
		}
		buf := make([]byte, segs*n)
		for ctx.Err() == nil {
			if _, _, err := uc.WriteMsgUDP(buf, oob, dst); err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return nil
				}
				if errors.Is(err, syscall.ENOBUFS) {
					continue
				}
				return fmt.Errorf("send UDP with GSO: %w", err)
			}
			sent.Add(uint64(segs))
		}
		return nil
	}
	pc := ipv4.NewPacketConn(uc)
	buf := make([]byte, n)
	msgs := make([]ipv4.Message, udpBatch)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{buf}
		msgs[i].Addr = dst
	}
	for ctx.Err() == nil {
		k, err := pc.WriteBatch(msgs, 0)
		sent.Add(uint64(max(k, 0)))
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if errors.Is(err, syscall.ENOBUFS) {
				continue
			}
			return fmt.Errorf("send UDP batch: %w", err)
		}
	}
	return nil
}

// receiveUDP counts packets with recvmmsg until uc closes.
func receiveUDP(uc *net.UDPConn, received *atomic.Uint64) error {
	pc := ipv4.NewPacketConn(uc)
	msgs := make([]ipv4.Message, udpBatch)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 2048)}
	}
	for {
		n, err := pc.ReadBatch(msgs, 0)
		if err != nil {
			return err
		}
		received.Add(uint64(n))
	}
}
