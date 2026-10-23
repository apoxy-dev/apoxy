package main

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// relayLinkENI is the -relay-link value of the ENI with device index 1 of an EC2
// host, which a production relay node uses.
const relayLinkENI = "eni1"

// relayNetworkFile tells systemd-networkd to leave the relay link alone, as the
// boot script of a production relay node does.
const relayNetworkFile = "/etc/systemd/network/10-apoxy-perf-relay.network"

// LinkRecord is what "perfrig node -relay-link" records of the relay link while
// the relay runs.
type LinkRecord struct {
	Dev      string `json:"dev"`
	MAC      string `json:"mac,omitempty"`
	Channels uint32 `json:"channels"`
	MTU      int    `json:"mtu"`
	// XDPMode is the attach mode of the XDP program while the relay ran: driver,
	// generic or offload. Empty: no program.
	XDPMode string `json:"xdp_mode,omitempty"`
	// XSKSockets are the AF_XDP sockets on the link and ZeroCopySockets are the
	// sockets in zero-copy mode, in the last read while the relay ran.
	XSKSockets      int  `json:"xsk_sockets"`
	ZeroCopySockets int  `json:"zero_copy_sockets"`
	ZeroCopy        bool `json:"zero_copy"`
	// XSKStats are the sums of the kernel counters of the sockets in the last read.
	XSKStats map[string]uint64 `json:"xsk_stats,omitempty"`
	// DiagError tells why the kernel did not give the sockets, for example
	// because it has no xsk_diag module.
	DiagError string `json:"diag_error,omitempty"`
	// CarrierDowns is the increase of the carrier down count of the link. ENA also
	// takes the link down and up when the relay sets up XDP and each zero-copy socket.
	CarrierDowns int64 `json:"carrier_downs"`
	// Resets is the number of link resets after an error: see linkResets.
	Resets int64 `json:"resets"`
	// XSKCounters are the sums over the queues of the increase of the ENA AF_XDP
	// counters, by name without the queue, for example tx_xsk_cnt.
	XSKCounters map[string]int64 `json:"xsk_counters,omitempty"`
	// Kmsg are the kernel log lines about the link or ENA while the relay ran.
	Kmsg []string `json:"kmsg,omitempty"`
}

// linkResets returns the increase of the ENA counter total_resets in the NIC
// counter increases nic, or carrierDowns when the link has no such counter.
func linkResets(nic map[string]int64, carrierDowns int64) int64 {
	if n, ok := nic["total_resets"]; ok {
		return n
	}
	return carrierDowns
}

// xskSocket is one AF_XDP socket as the kernel reports it.
type xskSocket struct {
	ifindex  uint32
	zeroCopy bool
	stats    map[string]uint64
}

// xskSummary counts the sockets on the link ifindex and the sockets in
// zero-copy mode, and sums their counters.
func xskSummary(socks []xskSocket, ifindex uint32) (n, zeroCopy int, stats map[string]uint64) {
	for _, s := range socks {
		if s.ifindex != ifindex {
			continue
		}
		n++
		if s.zeroCopy {
			zeroCopy++
		}
		for k, v := range s.stats {
			if stats == nil {
				stats = map[string]uint64{}
			}
			stats[k] += v
		}
	}
	return n, zeroCopy, stats
}

// queueXSKCounter matches an AF_XDP counter of one ENA queue.
var queueXSKCounter = regexp.MustCompile(`^queue_\d+_((tx|rx)_xsk_[a-z_]+)$`)

// sumXSKCounters returns the sum over the queues of each AF_XDP counter in d.
func sumXSKCounters(d map[string]int64) map[string]int64 {
	var out map[string]int64
	for k, v := range d {
		m := queueXSKCounter.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		if out == nil {
			out = map[string]int64{}
		}
		out[m[1]] += v
	}
	return out
}

// kmsgMax is the most kernel log lines in a record.
const kmsgMax = 100

// kmsgLine reads a /dev/kmsg record "PRI,SEQ,USEC,FLAGS;MESSAGE" and returns its
// time in microseconds after the boot and its message.
func kmsgLine(rec string) (usec uint64, msg string, ok bool) {
	head, msg, ok := strings.Cut(rec, ";")
	if !ok {
		return 0, "", false
	}
	f := strings.Split(head, ",")
	if len(f) < 3 {
		return 0, "", false
	}
	usec, err := strconv.ParseUint(f[2], 10, 64)
	if err != nil {
		return 0, "", false
	}
	// The lines after the first are key=value pairs.
	msg, _, _ = strings.Cut(msg, "\n")
	return usec, msg, true
}

// kmsgMatch reports whether a kernel log line is about the link dev or the ENA driver.
func kmsgMatch(msg, dev string) bool {
	return strings.Contains(msg, dev) || strings.HasPrefix(msg, "ena ") || strings.HasPrefix(msg, "ena:")
}

// kernelConfig returns the value of the option name in a kernel config: y, m,
// or n when it is not set. It returns "" when the config does not have it.
func kernelConfig(r io.Reader, name string) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "# "+name+" is not set" {
			return "n"
		}
		if v, ok := strings.CutPrefix(line, name+"="); ok {
			return v
		}
	}
	return ""
}

// irqTimeAccounting returns the CONFIG_IRQ_TIME_ACCOUNTING value of the running
// kernel, or "" when the host has no readable config. With it off, /proc/stat
// shows too little softirq time.
func irqTimeAccounting() string {
	const name = "CONFIG_IRQ_TIME_ACCOUNTING"
	if f, err := os.Open("/boot/config-" + kernelRelease()); err == nil {
		defer f.Close()
		return kernelConfig(f, name)
	}
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return ""
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return ""
	}
	return kernelConfig(gz, name)
}
