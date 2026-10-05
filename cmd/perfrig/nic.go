package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ethtoolCounters are the "ethtool -S" counters that the node result keeps.
// The allowance counters are the EC2 network limits of the ENA driver.
var ethtoolCounters = []string{
	"bw_in_allowance_exceeded",
	"bw_out_allowance_exceeded",
	"pps_allowance_exceeded",
	"conntrack_allowance_exceeded",
	"linklocal_allowance_exceeded",
}

// sysfsCounters are the drop counters in /sys/class/net/DEV/statistics.
var sysfsCounters = []string{"rx_dropped", "tx_dropped", "rx_over_errors", "rx_missed_errors"}

// udpCounters are the Udp counters of /proc/net/snmp of the host, by result
// name. A UDP GSO message and a UDP GRO message count as one datagram.
var udpCounters = map[string]string{
	"InDatagrams":  "udp_in_datagrams",
	"OutDatagrams": "udp_out_datagrams",
	"InErrors":     "udp_in_errors",
	"RcvbufErrors": "udp_rcvbuf_errors",
	"SndbufErrors": "udp_sndbuf_errors",
}

// topQueueKey is the percent of the RX packets that the busiest RX queue got.
const topQueueKey = "rx_top_queue_pct"

// nicCounterNames are the NIC counters of the summary, in order.
var nicCounterNames = append(append(slices.Clone(ethtoolCounters), sysfsCounters...), topQueueKey)

// rxQueuePackets matches the RX packet counter of one queue in "ethtool -S".
// txQueueCounters matches the TX packet counter of one queue, and how often
// its ring was full and the driver stopped it.
var (
	rxQueuePackets  = regexp.MustCompile(`^queue_\d+_rx_cnt$`)
	txQueueCounters = regexp.MustCompile(`^queue_\d+_tx_(cnt|queue_stop|queue_wakeup)$`)
)

// defaultDev returns the device of the default IPv4 route.
func defaultDev() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	return parseDefaultRoute(string(data))
}

// parseDefaultRoute finds the device of the route to 0.0.0.0 in /proc/net/route.
func parseDefaultRoute(data string) (string, error) {
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 2 {
			continue
		}
		if f[1] == "00000000" {
			return f[0], nil
		}
	}
	return "", errors.New("no default route in /proc/net/route")
}

// devIPv4 returns the first IPv4 address of dev.
func devIPv4(dev string) (string, error) {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return ipn.IP.String(), nil
		}
	}
	return "", fmt.Errorf("%s has no IPv4 address", dev)
}

// nicFacts reads the driver, the queues and the XDP features of dev. A part
// that it cannot read stays empty.
func nicFacts(ctx context.Context, dev string) *NIC {
	n := &NIC{Dev: dev}
	if ifi, err := net.InterfaceByName(dev); err == nil {
		n.MTU = ifi.MTU
	}
	if out, err := command(ctx, "ethtool", "-i", dev); err == nil {
		n.Driver, n.Version, n.Firmware = parseEthtoolInfo(out)
	}
	if queues, err := filepath.Glob("/sys/class/net/" + dev + "/queues/rx-*"); err == nil {
		n.RxQueues = len(queues)
	}
	n.XDPFeatures, n.XDPZCMaxSegs = xdpFeatures(dev)
	return n
}

// parseEthtoolInfo reads the driver, version and firmware-version lines of "ethtool -i".
func parseEthtoolInfo(out string) (driver, version, firmware string) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "driver":
			driver = v
		case "version":
			version = v
		case "firmware-version":
			firmware = v
		}
	}
	return driver, version, firmware
}

// nicCounters returns the ethtool counters, the RX packets of each queue and
// the sysfs drop counters of dev, and the UDP counters of the host. It returns
// nil when it can read none of them.
func nicCounters(ctx context.Context, dev string) map[string]int64 {
	got := map[string]int64{}
	if b, err := os.ReadFile("/proc/net/snmp"); err == nil {
		maps.Copy(got, parseSNMP(string(b), "Udp", udpCounters))
	}
	if _, err := exec.LookPath("ethtool"); err == nil {
		if out, err := command(ctx, "ethtool", "-S", dev); err == nil {
			maps.Copy(got, parseEthtoolStats(out, ethtoolCounters))
		}
	}
	for _, name := range sysfsCounters {
		b, err := os.ReadFile(filepath.Join("/sys/class/net", dev, "statistics", name))
		if err != nil {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			got[name] = n
		}
	}
	if len(got) == 0 {
		return nil
	}
	return got
}

// parseEthtoolStats reads the "name: value" lines of "ethtool -S" whose name
// is in names or is a packet counter of a queue. It returns nil when none is there.
func parseEthtoolStats(out string, names []string) map[string]int64 {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var got map[string]int64
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		k = strings.TrimSpace(k)
		if !ok || !(want[k] || rxQueuePackets.MatchString(k) || txQueueCounters.MatchString(k)) {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		if got == nil {
			got = map[string]int64{}
		}
		got[k] = n
	}
	return got
}

// parseSNMP reads the counters of one group of /proc/net/snmp that names has,
// under their result names. Each group has a line of names and then a line of values.
func parseSNMP(data, group string, names map[string]string) map[string]int64 {
	got := map[string]int64{}
	var head []string
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != group+":" {
			continue
		}
		if head == nil {
			head = f
			continue
		}
		for i, v := range f[:min(len(f), len(head))] {
			key, ok := names[head[i]]
			if !ok {
				continue
			}
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				got[key] = n
			}
		}
		break
	}
	return got
}

// counterDeltas returns the increase of each counter from a to b, for the
// counters that both have, and the share of the busiest RX queue.
func counterDeltas(a, b map[string]int64) map[string]int64 {
	if a == nil || b == nil {
		return nil
	}
	d := make(map[string]int64, len(b))
	for k, v1 := range b {
		if v0, ok := a[k]; ok {
			d[k] = max(v1-v0, 0)
		}
	}
	if p := topQueuePercent(d); p >= 0 {
		d[topQueueKey] = p
	}
	return d
}

// topQueuePercent returns the percent of the RX packets that the busiest queue
// got, or -1 when no queue got packets. One UDP flow goes to one queue.
func topQueuePercent(d map[string]int64) int64 {
	var total, top int64
	for k, v := range d {
		if rxQueuePackets.MatchString(k) {
			total += v
			top = max(top, v)
		}
	}
	if total == 0 {
		return -1
	}
	return top * 100 / total
}

// maxCounters returns the larger value of each counter of a and b.
func maxCounters(a, b map[string]int64) map[string]int64 {
	if a == nil {
		return b
	}
	out := maps.Clone(a)
	for k, v := range b {
		if old, ok := out[k]; !ok || v > old {
			out[k] = v
		}
	}
	return out
}

// peakCounters reads the counters of dev each interval. The returned function stops
// the reads and returns the largest value of each counter. ENA sets the counters of
// its queues to 0 when an XDP program goes off the link.
func peakCounters(ctx context.Context, dev string, interval time.Duration) func() map[string]int64 {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan map[string]int64, 1)
	go func() {
		var peak map[string]int64
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- peak
				return
			case <-t.C:
				peak = maxCounters(peak, nicCounters(ctx, dev))
			}
		}
	}()
	return func() map[string]int64 {
		cancel()
		return <-done
	}
}

const (
	// xdpMaxMTU is the largest MTU with which the ENA driver takes an XDP program.
	xdpMaxMTU = 3498
	// linkSettle is the time that the address must stay on a link after a change.
	linkSettle = 2 * time.Second
)

// linkConf is the settings of a link that an XDP program in driver mode needs.
type linkConf struct {
	channels   uint32 // Combined channels. With XDP, ENA needs one more TX queue for each.
	mtu        int
	forwarding string // IPv4 forwarding of the link: "0" or "1".
}

// xdpConf returns c with the settings for XDP in driver mode on ENA: at most half of
// maxChannels, a small MTU, and forwarding for the next hop lookup of the program.
func xdpConf(c linkConf, maxChannels uint32) linkConf {
	c.channels = min(c.channels, max(maxChannels/2, 1))
	c.mtu = min(c.mtu, xdpMaxMTU)
	c.forwarding = "1"
	return c
}

// xdpFeatureNames are the NETDEV_XDP_ACT_* bits of the netdev API, by bit position.
var xdpFeatureNames = []string{"basic", "redirect", "ndo-xmit", "xsk-zerocopy", "hw-offload", "rx-sg", "ndo-xmit-sg"}

// xdpFeatureList returns the names of the bits set in the feature mask.
func xdpFeatureList(mask uint64) []string {
	var names []string
	for i, n := range xdpFeatureNames {
		if mask&(1<<i) != 0 {
			names = append(names, n)
		}
	}
	for i := len(xdpFeatureNames); i < 64; i++ {
		if mask&(1<<i) != 0 {
			names = append(names, "bit"+strconv.Itoa(i))
		}
	}
	return names
}
