// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package egressfwd

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestServeDNSOverTCP drives one guest DNS-over-TCP query through the bridge to
// a fake unixgram resolver and asserts the framed reply comes back intact AND
// feeds the shared answer cache — so a name resolved only over TCP:53 (a
// truncated-UDP retry) is still attributable for egress policy. This is the
// path that must NOT be stolen by the catch-all TCP egress forwarder.
func TestServeDNSOverTCP(t *testing.T) {
	// Fake resident resolver on an abstract unixgram socket: reply to each
	// query with an A record for the queried name.
	sock := fmt.Sprintf("@apoxy-test-resolver-%d", os.Getpid())
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatalf("bind fake resolver: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	answerIP := net.IPv4(1, 2, 3, 4)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: answerIP,
			})
			b, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = ln.WriteTo(b, addr)
		}
	}()

	cache := newDNSCache()
	client, guest := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- serveDNSOverTCP(guest, sock, cache) }()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	// Frame and send the guest's query (2-byte length prefix + message).
	req := new(dns.Msg)
	req.SetQuestion("api.example.com.", dns.TypeA)
	q, err := req.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(q)))
	if _, err := client.Write(lp[:]); err != nil {
		t.Fatalf("write length prefix: %v", err)
	}
	if _, err := client.Write(q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	// Read the framed reply.
	if _, err := io.ReadFull(client, lp[:]); err != nil {
		t.Fatalf("read reply length: %v", err)
	}
	rlen := binary.BigEndian.Uint16(lp[:])
	respBuf := make([]byte, rlen)
	if _, err := io.ReadFull(client, respBuf); err != nil {
		t.Fatalf("read reply body: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respBuf); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d; want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(answerIP) {
		t.Fatalf("answer = %v; want A %s", resp.Answer[0], answerIP)
	}

	// The response fed the cache, so the resolved IP attributes to the qname.
	if got := cache.Lookup(netip.AddrFrom4([4]byte{1, 2, 3, 4})); got != "api.example.com" {
		t.Errorf("cache Lookup = %q; want api.example.com (TCP answer must be cached)", got)
	}

	// Closing the guest connection ends the bridge cleanly (EOF → nil).
	_ = client.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("serveDNSOverTCP returned %v; want nil on guest close", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serveDNSOverTCP did not return after guest close")
	}
}
