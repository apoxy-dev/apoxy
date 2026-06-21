//go:build linux

package sandbox

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

// writeSandboxResolvConf materializes a per-sandbox /etc/resolv.conf
// pointing at the per-sandbox gateway IP. The file is bind-mounted over
// the sandbox's /etc/resolv.conf at create time.
//
// We can't use a loopback nameserver here: loopback addresses route via
// `lo` inside the sandbox, where nothing listens on :53, so the DNS query
// never reaches the gVisor netstack. The gateway IP, on the other hand,
// is the only off-link address the sandbox's default route knows about —
// packets to it land on eth0 (loopether) and get picked up by an
// installed UDP/DNS forwarder, which rewrites the destination to a real
// resolver before dialing out.
func (m *Manager) writeSandboxResolvConf(id SandboxID, gw netip.Addr) (string, error) {
	dir := filepath.Join(m.rootDir, string(id)+"-net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating netconfig dir: %w", err)
	}
	path := filepath.Join(dir, "resolv.conf")
	// ndots:0 keeps glibc/musl from prepending search domains and burning
	// round-trips on suffixed queries that will all NXDOMAIN.
	content := fmt.Sprintf("nameserver %s\noptions ndots:0\n", gw.String())
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("writing resolv.conf: %w", err)
	}
	return path, nil
}

// removeSandboxNetConfig cleans up the per-sandbox netconfig dir on
// sandbox delete.
func (m *Manager) removeSandboxNetConfig(id SandboxID) {
	_ = os.RemoveAll(filepath.Join(m.rootDir, string(id)+"-net"))
}

// resolvMountSpec returns the bind mount that overlays the host-written
// per-sandbox resolv.conf onto the sandbox's /etc/resolv.conf.
func resolvMountSpec(source string) Mount {
	return Mount{
		Destination: "/etc/resolv.conf",
		Source:      source,
		Type:        "bind",
		Options:     []string{"bind", "ro"},
	}
}
