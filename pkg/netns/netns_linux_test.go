// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package netns

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
)

// TestDialTimeoutInNamespace exercises the real thing: create a named netns,
// bring its loopback up, listen inside it, and DialTimeout into it via the
// bind-mount path — proving the socket is created in the target namespace and
// the calling goroutine's thread is restored.
func TestDialTimeoutInNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_SYS_ADMIN) to create network namespaces")
	}
	name := fmt.Sprintf("apoxy-netns-test-%d", os.Getpid())
	ns, err := EnsureNamed(name)
	if err != nil {
		t.Fatalf("EnsureNamed: %v", err)
	}
	t.Cleanup(func() {
		ns.Close()
		_ = vnetns.DeleteNamed(name)
	})

	// A fresh namespace has loopback down; bring it up so the listener binds.
	nl, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatalf("netlink handle in netns: %v", err)
	}
	defer nl.Close()
	lo, err := nl.LinkByName("lo")
	if err != nil {
		t.Fatalf("loopback in netns: %v", err)
	}
	if err := nl.LinkSetUp(lo); err != nil {
		t.Fatalf("bring up loopback: %v", err)
	}

	// Listen inside the namespace. The listener fd keeps its namespace no
	// matter which thread later accepts on it.
	var ln net.Listener
	if err := Do(ns, func() error {
		var lerr error
		ln, lerr = net.Listen("tcp", "127.0.0.1:0")
		return lerr
	}); err != nil {
		t.Fatalf("listen in netns: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("ok"))
		c.Close()
	}()

	// The same address in the CURRENT namespace must be unreachable (nothing
	// listens there), proving the netns dial below isn't accidentally local.
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatalf("dial of %s unexpectedly succeeded in the host netns", ln.Addr())
	}

	conn, err := DialTimeout("/var/run/netns/"+name, "tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout into netns: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read from netns listener: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("got %q; want %q", buf, "ok")
	}
}
