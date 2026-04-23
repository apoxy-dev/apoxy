//go:build linux

package metrics

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Kernel-level collectors for tunnel observability. Registered in init() so
// any process that links this package (agent or server) exposes them on its
// /metrics endpoint. Scraped on demand — no goroutines or caching — so the
// reported values track kernel state at scrape time.
//
// TODO(APO-543): the PTB counters exist so we can detect "ICMPv6 PTB not
// arriving" conditions like the one that caused the Tailscale 1280-MTU
// blackhole in trainy. Remove or repurpose once PTB propagation is fixed
// end-to-end.

// Interfaces we care about for MTU reporting. Missing interfaces (e.g. the
// server-side backplane has no tun0, agent has no gnv0) are silently skipped.
var tunnelInterfaceMTUs = []string{"tun0", "gnv0"}

type kernelCollector struct {
	mtu       *prometheus.Desc
	icmp6InPB *prometheus.Desc
	icmp6OuPB *prometheus.Desc
}

func newKernelCollector() *kernelCollector {
	return &kernelCollector{
		mtu: prometheus.NewDesc(
			"tunnel_interface_mtu_bytes",
			"Current MTU (bytes) of the named tunnel interface, read from /sys/class/net/<iface>/mtu.",
			[]string{"interface"},
			nil,
		),
		icmp6InPB: prometheus.NewDesc(
			"tunnel_icmp6_packet_too_big_in_total",
			"Cumulative ICMPv6 Packet-Too-Big messages received by the kernel in this netns (Icmp6InPktTooBigs from /proc/net/snmp6). Zero under a PMTUD blackhole.",
			nil,
			nil,
		),
		icmp6OuPB: prometheus.NewDesc(
			"tunnel_icmp6_packet_too_big_out_total",
			"Cumulative ICMPv6 Packet-Too-Big messages emitted by the kernel in this netns (Icmp6OutPktTooBigs from /proc/net/snmp6).",
			nil,
			nil,
		),
	}
}

func (c *kernelCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.mtu
	ch <- c.icmp6InPB
	ch <- c.icmp6OuPB
}

func (c *kernelCollector) Collect(ch chan<- prometheus.Metric) {
	for _, iface := range tunnelInterfaceMTUs {
		if v, ok := readUintFile("/sys/class/net/" + iface + "/mtu"); ok {
			ch <- prometheus.MustNewConstMetric(c.mtu, prometheus.GaugeValue, float64(v), iface)
		}
	}
	if counters, ok := readSNMP6(); ok {
		if v, ok := counters["Icmp6InPktTooBigs"]; ok {
			ch <- prometheus.MustNewConstMetric(c.icmp6InPB, prometheus.CounterValue, float64(v))
		}
		if v, ok := counters["Icmp6OutPktTooBigs"]; ok {
			ch <- prometheus.MustNewConstMetric(c.icmp6OuPB, prometheus.CounterValue, float64(v))
		}
	}
}

func readUintFile(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func readSNMP6() (map[string]uint64, bool) {
	f, err := os.Open("/proc/net/snmp6")
	if err != nil {
		return nil, false
	}
	defer f.Close()
	out := make(map[string]uint64, 4)
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		out[fields[0]] = v
	}
	return out, true
}

func init() {
	metrics.Registry.MustRegister(newKernelCollector())
}
