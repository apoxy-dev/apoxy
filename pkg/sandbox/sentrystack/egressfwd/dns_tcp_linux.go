// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package egressfwd

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"
)

// dnsTCPQueryTimeout bounds one guest TCP:53 query's round-trip to the resident
// resolver over the unixgram socket. DNS is loopback-fast; the bound only keeps
// a wedged resolver from pinning the forwarder goroutine until the guest gives
// up.
const dnsTCPQueryTimeout = 5 * time.Second

// serveDNSOverTCP bridges the guest's DNS-over-TCP (RFC 1035 §4.2.2:
// 2-byte length prefix + message) connection to the resident's unixgram
// resolver. It exists so a truncated UDP answer (TC=1) — whose stub retries
// over TCP:53 — reaches the SAME resolver plane instead of being stolen by the
// catch-all TCP egress forwarder and SSRF-denied as a private gateway address.
//
// Queries are handled sequentially over one reused unixgram conn: a stub opens
// a fresh TCP connection per retried query and rarely pipelines, so this is
// both correct and simple. Response payloads feed the shared DNS-answer cache
// so a name resolved only over TCP is still attributable for egress policy.
func serveDNSOverTCP(guest net.Conn, resolverSock string, cache *dnsCache) error {
	up, err := dialUnixgram(resolverSock)
	if err != nil {
		return err
	}
	defer up.Close()

	// One 64KiB scratch buffer: a DNS-over-TCP message is bounded by the 2-byte
	// length prefix (<= 65535), which is exactly the datagram the resolver
	// replies with.
	buf := udpBuffPool.Get().(*[]byte)
	defer udpBuffPool.Put(buf)
	scratch := *buf

	var lenBuf [2]byte
	for {
		// Read the guest's length-prefixed query.
		if _, err := io.ReadFull(guest, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		qlen := binary.BigEndian.Uint16(lenBuf[:])
		if int(qlen) > len(scratch) {
			// A query larger than any datagram we could relay: abandon the
			// connection rather than truncate it.
			return errors.New("dns-over-tcp query exceeds datagram size")
		}
		if _, err := io.ReadFull(guest, scratch[:qlen]); err != nil {
			return err
		}

		// Relay as one datagram to the resolver and read its reply.
		if err := up.SetDeadline(time.Now().Add(dnsTCPQueryTimeout)); err != nil {
			return err
		}
		if _, err := up.Write(scratch[:qlen]); err != nil {
			return err
		}
		n, err := up.Read(scratch)
		if err != nil {
			return err
		}
		if cache != nil {
			cache.IngestResponse(scratch[:n])
		}

		// Frame the reply back to the guest.
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		if _, err := guest.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := guest.Write(scratch[:n]); err != nil {
			return err
		}
	}
}

// logDNSOverTCPExit downgrades the ordinary end-of-connection errors to debug.
func logDNSOverTCPExit(logger *slog.Logger, err error) {
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		logger.Debug("DNS-over-TCP connection closed")
	default:
		logger.Warn("DNS-over-TCP bridge error", "error", err)
	}
}
