// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/net/dns"
	"github.com/apoxy-dev/apoxy/pkg/net/dns/vpcdns"
	"github.com/apoxy-dev/apoxy/pkg/sandbox"
)

// residentDNS is the resident's DNS listener: a per-resident unixgram socket
// serving the pushed VPC name plane (authoritative bindings) chained to
// cache -> upstream (the pod's /etc/resolv.conf), so a worker's getaddrinfo
// resolves both VPC and external names. The in-Sentry :53 forwarder dials
// the socket; its address is sealed into the sandbox spec as
// EgressInit.DNSResolvers, so — like the egress bridge — it must be up
// before the resident starts and dies with the resident (no port
// allocation, no cross-tenant registry, no teardown leak).
type residentDNS struct {
	conn *net.UnixConn
	// target is the resolver entry sealed into InitStr.DNSResolvers
	// ("unix://<name>", where an "@"-prefixed name is a Linux
	// abstract-namespace socket).
	target string
	closed atomic.Bool
}

// dnsSocketName picks the resident's DNS socket name. On Linux it is an
// ABSTRACT unix socket ("@..."): abstract names live in the network
// namespace — which the Sentry shares with the host (pod) — not the
// filesystem, so the chrooted Sentry can dial it where a filesystem path
// would be unreachable. Elsewhere (unit tests on macOS) a temp filesystem
// path stands in; production sandboxes are Linux-only.
func dnsSocketName(id sandbox.SandboxID) string {
	if runtime.GOOS == "linux" {
		return "@apoxy-dns-" + string(id)
	}
	return filepath.Join(os.TempDir(), "apoxy-dns-"+string(id)+".sock")
}

// startResidentDNS binds the resident's DNS socket and starts serving source's
// snapshot. Reachability is the tenant boundary: the socket is only dialable
// from the pod's network namespace, and each Sentry's forwarder is pinned at
// boot to its own resident's socket, so per-query authentication is
// unnecessary — exactly the loopback-port model this replaces, minus the port
// management.
func startResidentDNS(id sandbox.SandboxID, source func() vpcdns.Snapshot) (*residentDNS, error) {
	name := dnsSocketName(id)
	if !strings.HasPrefix(name, "@") {
		// A leftover filesystem socket from a previous incarnation blocks the
		// bind; the resident is the only legitimate binder of its path.
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("removing stale resident DNS socket %s: %w", name, err)
		}
	}
	handler := &vpcdns.Handler{Source: source, Name: "resident-dns"}
	// Construct the server BEFORE binding/serving so a construction failure
	// (e.g. /etc/resolv.conf unreadable → the upstream plugin can't load) is
	// returned synchronously and fails resident boot loudly, rather than
	// binding a socket nothing serves — which would stall every worker
	// getaddrinfo to timeout with the sandbox looking healthy.
	srv, err := dns.NewPacketServer(dns.WithPlugins(handler.Plugin))
	if err != nil {
		return nil, fmt.Errorf("constructing resident DNS server: %w", err)
	}

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return nil, fmt.Errorf("binding resident DNS socket %s: %w", name, err)
	}

	d := &residentDNS{conn: conn, target: "unix://" + name}
	go func() {
		// Serve exits with a read error when close() closes the conn; only an
		// exit while the resolver is supposed to be up is worth a warning (the
		// sandbox keeps running but hostname egress degrades to literal-IP-only
		// until the resident is recreated).
		err := srv.Serve(namedSenderOnly{conn})
		if !d.closed.Load() {
			slog.Warn("Resident DNS listener exited unexpectedly",
				"sandbox.id", string(id), "socket", name, "error", err)
		}
	}()
	return d, nil
}

// namedSenderOnly drops datagrams from senders with no bound address. An
// unbound unix dgram client is anonymous (Linux does not autobind on
// connect(2)), so it can never receive a reply — and a nil remote address
// panics the DNS server deep in miekg/dns's response bookkeeping. Every
// legitimate client (the Sentry's dialUnixgram) binds an abstract name.
type namedSenderOnly struct {
	net.PacketConn
}

func (c namedSenderOnly) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err == nil && anonymousAddr(addr) {
			slog.Warn("Dropping DNS query from an anonymous (unbound) unixgram sender")
			continue
		}
		return n, addr, err
	}
}

// anonymousAddr reports whether addr names no reply destination.
func anonymousAddr(addr net.Addr) bool {
	if addr == nil {
		return true
	}
	ua, ok := addr.(*net.UnixAddr)
	return ok && (ua == nil || ua.Name == "" || ua.Name == "@")
}

// close tears the listener down. Idempotent; the abstract name (or unlinked
// path) is released with the conn.
func (d *residentDNS) close() error {
	if d == nil {
		return nil
	}
	d.closed.Store(true)
	err := d.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
