package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "tunbench"

// datagramConn is the part of a QUIC connection that the fork and stock
// quic-go both have.
type datagramConn interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	CloseWithError(quic.ApplicationErrorCode, string) error
}

// quicSender sends each packet in one DATAGRAM frame.
type quicSender struct {
	conn datagramConn
	pkt  []byte
}

// dialQUIC connects to the relay and waits until a packet of the tunnel MTU
// fits in one datagram. Path MTU discovery starts at InitialPacketSize, which
// is too small for it. Stock quic-go sends MTU probes only when it sends other
// packets, so the wait sends smaller datagrams.
func dialQUIC(ctx context.Context, o options, conn *net.UDPConn, relay *net.UDPAddr, pkt []byte) (*quicSender, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The relay has a self-signed certificate.
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}}
	c, err := quic.Dial(ctx, conn, relay, tlsConf, quicConfig(o))
	if err != nil {
		return nil, fmt.Errorf("dial QUIC: %w", err)
	}
	start := time.Now()
	for {
		err := c.SendDatagram(pkt)
		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			if err != nil {
				c.CloseWithError(0, "")
				return nil, err
			}
			slog.Info("Connected to the relay", "mtu_wait", time.Since(start))
			return &quicSender{conn: c, pkt: pkt}, nil
		}
		if err := c.SendDatagram(pkt[:min(len(pkt), int(tooLarge.MaxDatagramPayloadSize))]); err != nil {
			c.CloseWithError(0, "")
			return nil, err
		}
		select {
		case <-ctx.Done():
			c.CloseWithError(0, "")
			return nil, fmt.Errorf("a %d byte datagram does not fit after 10 s (max %d)", len(pkt), tooLarge.MaxDatagramPayloadSize)
		case <-time.After(time.Millisecond):
		}
	}
}

func (s *quicSender) send() (int, error) {
	if err := s.conn.SendDatagram(s.pkt); err != nil {
		return 0, err
	}
	return 1, nil
}

func (s *quicSender) Close() error { return s.conn.CloseWithError(0, "done") }

// receiveQUIC accepts one connection and counts its datagrams.
func receiveQUIC(ctx context.Context, o options, conn *net.UDPConn, c *counter) error {
	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}
	ln, err := quic.Listen(conn, tlsConf, quicConfig(o))
	if err != nil {
		return err
	}
	defer ln.Close()
	qc, err := ln.Accept(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("accept QUIC connection: %w", err)
	}
	return countDatagrams(ctx, qc, c)
}

func countDatagrams(ctx context.Context, qc datagramConn, c *counter) error {
	defer qc.CloseWithError(0, "")
	for {
		b, err := qc.ReceiveDatagram(ctx)
		if err != nil {
			var appErr *quic.ApplicationError
			if ctx.Err() != nil || (errors.As(err, &appErr) && appErr.Remote) {
				return nil
			}
			return fmt.Errorf("receive datagram: %w", err)
		}
		c.add(1, uint64(len(b)))
	}
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{alpn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// recordSeparator starts each qlog record (JSON text sequences, RFC 7464).
const recordSeparator = 0x1e

// qlogWriter writes qlog records until the file has max bytes and drops the
// later ones, so that a long run gives a small file. quic-go writes the record
// separator in its own Write call, so the file ends on a full record.
type qlogWriter struct {
	w      *bufio.Writer
	c      io.Closer
	max, n int64
	cut    bool
}

func newQlogWriter(dir string, isClient bool, id fmt.Stringer, limit int64) (*qlogWriter, error) {
	side := "relay"
	if isClient {
		side = "agent"
	}
	f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s_%s_%s.sqlog", transportName("quic"), side, id)))
	if err != nil {
		return nil, err
	}
	return &qlogWriter{w: bufio.NewWriterSize(f, 64<<10), c: f, max: limit}, nil
}

func (q *qlogWriter) Write(p []byte) (int, error) {
	if !q.cut && len(p) > 0 && p[0] == recordSeparator && q.n >= q.max {
		q.cut = true
	}
	if q.cut {
		return len(p), nil
	}
	n, err := q.w.Write(p)
	q.n += int64(n)
	return n, err
}

func (q *qlogWriter) Close() error {
	return errors.Join(q.w.Flush(), q.c.Close())
}
