package envoy

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processStats are the resource counters of a running process.
type processStats struct {
	// OpenFDs is the number of open file descriptors.
	OpenFDs int64
	// MaxFDs is the soft limit on open file descriptors. It is zero when the
	// limit is unknown or unlimited.
	MaxFDs int64
	// RSSBytes is the resident memory of the process.
	RSSBytes int64
}

// processReader reads the resource counters of a running process.
type processReader interface {
	ProcessStats(pid int) (processStats, error)
}

// tcpCounters are the kernel TCP counters of the network namespace. The
// backplane shares the namespace with Envoy, so the counters cover both.
type tcpCounters struct {
	// OutRsts counts the resets the kernel sent.
	OutRsts int64
	// EstabResets counts the established connections that were reset.
	EstabResets int64
	// AbortOnClose counts the connections aborted on close with unread data.
	AbortOnClose int64
	// AbortOnData counts the connections aborted because data arrived after
	// close.
	AbortOnData int64
	// ListenOverflows counts the connections dropped because the accept queue
	// was full.
	ListenOverflows int64
	// ListenDrops counts the connections the listening socket dropped.
	ListenDrops int64
}

// netReader reads the kernel TCP counters of the network namespace.
type netReader interface {
	TCPCounters() (tcpCounters, error)
}

// procfs reads the counters from a mounted proc filesystem.
type procfs struct {
	// root is the mount point of the proc filesystem.
	root string
	// pageSize is the size of a memory page in bytes.
	pageSize int64
}

// ProcessStats reads the file descriptor and memory counters of pid.
func (p *procfs) ProcessStats(pid int) (processStats, error) {
	dir := filepath.Join(p.root, strconv.Itoa(pid))

	open, err := countEntries(filepath.Join(dir, "fd"))
	if err != nil {
		return processStats{}, fmt.Errorf("failed to read the open file descriptors: %w", err)
	}
	s := processStats{OpenFDs: open}

	if b, err := os.ReadFile(filepath.Join(dir, "limits")); err == nil {
		s.MaxFDs = parseMaxOpenFiles(b)
	}

	b, err := os.ReadFile(filepath.Join(dir, "statm"))
	if err != nil {
		return s, fmt.Errorf("failed to read the process memory: %w", err)
	}
	s.RSSBytes = parseResidentBytes(b, p.pageSize)

	return s, nil
}

// countEntries counts the names in dir. It does not sort them, because a
// process with many open file descriptors is read on every scrape.
func countEntries(dir string) (int64, error) {
	f, err := os.Open(dir)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil {
		return 0, err
	}

	return int64(len(names)), nil
}

// TCPCounters reads the TCP counters of the network namespace.
func (p *procfs) TCPCounters() (tcpCounters, error) {
	snmp, err := os.ReadFile(filepath.Join(p.root, "net", "snmp"))
	if err != nil {
		return tcpCounters{}, fmt.Errorf("failed to read the TCP counters: %w", err)
	}
	netstat, err := os.ReadFile(filepath.Join(p.root, "net", "netstat"))
	if err != nil {
		return tcpCounters{}, fmt.Errorf("failed to read the extended TCP counters: %w", err)
	}

	c := parseProcNetCounters(snmp)
	for prefix, values := range parseProcNetCounters(netstat) {
		if c[prefix] == nil {
			c[prefix] = values
			continue
		}
		for k, v := range values {
			c[prefix][k] = v
		}
	}

	return tcpCounters{
		OutRsts:         c["Tcp"]["OutRsts"],
		EstabResets:     c["Tcp"]["EstabResets"],
		AbortOnClose:    c["TcpExt"]["TCPAbortOnClose"],
		AbortOnData:     c["TcpExt"]["TCPAbortOnData"],
		ListenOverflows: c["TcpExt"]["ListenOverflows"],
		ListenDrops:     c["TcpExt"]["ListenDrops"],
	}, nil
}

// parseProcNetCounters reads the line pairs of /proc/net/snmp and
// /proc/net/netstat. Each pair is a "<prefix>: <names>" line and a
// "<prefix>: <values>" line. The result maps the prefix and the name to the
// value.
func parseProcNetCounters(b []byte) map[string]map[string]int64 {
	out := make(map[string]map[string]int64)

	var names []string
	var prefix string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ":") {
			continue
		}

		if names == nil || prefix != strings.TrimSuffix(fields[0], ":") {
			prefix = strings.TrimSuffix(fields[0], ":")
			names = fields[1:]
			continue
		}

		values := out[prefix]
		if values == nil {
			values = make(map[string]int64, len(names))
			out[prefix] = values
		}
		for i, name := range names {
			if i+1 >= len(fields) {
				break
			}
			v, err := strconv.ParseInt(fields[i+1], 10, 64)
			if err != nil {
				continue
			}
			values[name] = v
		}
		names = nil
	}

	return out
}

// parseMaxOpenFiles reads the soft limit on open files from the
// /proc/<pid>/limits format. An unknown or unlimited value gives zero.
func parseMaxOpenFiles(b []byte) int64 {
	const name = "Max open files"

	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, name) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, name))
		if len(fields) == 0 {
			return 0
		}
		v, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return v
	}

	return 0
}

// parseResidentBytes reads the resident page count, the second field of
// /proc/<pid>/statm, and returns it in bytes.
func parseResidentBytes(b []byte, pageSize int64) int64 {
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}

	return pages * pageSize
}
