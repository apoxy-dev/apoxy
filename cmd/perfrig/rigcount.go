package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// rigSNMP are the counters of /proc/net/snmp that tell a drop in a netns, by group and result name.
var rigSNMP = map[string]map[string]string{
	"Ip": {
		"InHdrErrors": "ip/in_hdr_errors", "InAddrErrors": "ip/in_addr_errors", "InDiscards": "ip/in_discards",
		"OutDiscards": "ip/out_discards", "OutNoRoutes": "ip/out_no_routes",
	},
	"Udp": {
		"NoPorts": "udp/no_ports", "InErrors": "udp/in_errors", "RcvbufErrors": "udp/rcvbuf_errors",
		"SndbufErrors": "udp/sndbuf_errors", "InCsumErrors": "udp/csum_errors", "MemErrors": "udp/mem_errors",
	},
}

// softnetColumns are the columns of /proc/net/softnet_stat that the result keeps:
// drops at a full backlog, polls that used all their budget, and flow limit drops.
var softnetColumns = map[int]string{1: "softnet/dropped", 2: "softnet/time_squeeze", 10: "softnet/flow_limit"}

// vethQueueStat matches one queue counter of a veth in "ethtool -S".
var vethQueueStat = regexp.MustCompile(`^(rx|tx)_queue_(\d+)_(\w+)$`)

// counters returns the drop counters of each link, qdisc and netns of the rig by
// "netns/link/counter", and the softnet counters of the host.
func (r *rig) counters(ctx context.Context) map[string]int64 {
	got := map[string]int64{}
	var errs []error
	b, err := os.ReadFile("/proc/net/softnet_stat")
	errs = append(errs, err)
	maps.Copy(got, parseSoftnet(string(b)))
	add := func(ns, prefix string, m map[string]int64, err error) {
		errs = append(errs, err)
		for k, v := range m {
			got[strings.TrimPrefix(ns, r.cfg.NetnsPrefix+"-")+"/"+prefix+k] = v
		}
	}
	for _, ns := range []string{r.client, r.server, r.relay, r.bridge} {
		if ns == "" {
			continue
		}
		out, err := command(ctx, "ip", "-n", ns, "-j", "-s", "-s", "link", "show")
		if err == nil {
			var m map[string]int64
			m, err = parseLinkStats(out)
			add(ns, "", m, nil)
		}
		errs = append(errs, err)
		if out, err = command(ctx, "tc", "-n", ns, "-s", "-j", "qdisc", "show"); err == nil {
			var m map[string]int64
			m, err = parseQdiscStats(out)
			add(ns, "", m, nil)
		}
		errs = append(errs, err)
		out, err = command(ctx, "ip", "netns", "exec", ns, "cat", "/proc/net/snmp")
		for group, names := range rigSNMP {
			add(ns, "", parseSNMP(out, group, names), err)
		}
	}
	if _, err := exec.LookPath("ethtool"); err == nil {
		for _, v := range r.veths() {
			out, err := command(ctx, "ip", "netns", "exec", v.ns, "ethtool", "-S", v.dev)
			add(v.ns, v.dev+"/", parseVethStats(out), err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		slog.Warn("Failed to read some rig counters", "error", err)
	}
	return got
}

// parseLinkStats reads the JSON of "ip -j -s -s link show" and returns the drop
// and error counters of each link by "link/direction_counter".
func parseLinkStats(out string) (map[string]int64, error) {
	var links []struct {
		Name  string                    `json:"ifname"`
		Stats map[string]map[string]any `json:"stats64"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		return nil, err
	}
	got := map[string]int64{}
	for _, l := range links {
		for dir, stats := range l.Stats {
			for k, v := range stats {
				n, ok := v.(float64)
				if ok && (strings.Contains(k, "dropped") || strings.Contains(k, "errors")) {
					got[l.Name+"/"+dir+"_"+k] = int64(n)
				}
			}
		}
	}
	return got, nil
}

// parseQdiscStats reads the JSON of "tc -s -j qdisc show" and returns the sum of
// the counters of the qdiscs of each kind on each link, by "link/qdisc_kind_counter".
func parseQdiscStats(out string) (map[string]int64, error) {
	var qdiscs []struct {
		Kind       string `json:"kind"`
		Dev        string `json:"dev"`
		Drops      int64  `json:"drops"`
		Overlimits int64  `json:"overlimits"`
		Requeues   int64  `json:"requeues"`
	}
	if err := json.Unmarshal([]byte(out), &qdiscs); err != nil {
		return nil, err
	}
	got := map[string]int64{}
	for _, q := range qdiscs {
		p := q.Dev + "/qdisc_" + q.Kind + "_"
		got[p+"drops"] += q.Drops
		got[p+"overlimits"] += q.Overlimits
		got[p+"requeues"] += q.Requeues
	}
	return got, nil
}

// parseVethStats reads "ethtool -S" of a veth. It adds the drop and error counters
// of all queues, and keeps the packets that each RX queue took from its ring.
func parseVethStats(out string) map[string]int64 {
	got := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, ":")
		m := vethQueueStat.FindStringSubmatch(strings.TrimSpace(k))
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if m == nil || err != nil {
			continue
		}
		switch {
		case strings.HasSuffix(m[3], "drops"), strings.HasSuffix(m[3], "errors"):
			got[m[1]+"_queue_"+m[3]] += n
		case m[1] == "rx" && m[3] == "xdp_packets":
			got["rx_queue_"+m[2]+"_packets"] = n
		}
	}
	return got
}

// parseSoftnet adds softnetColumns of /proc/net/softnet_stat over the CPUs. Each
// line has the hex counters of one CPU.
func parseSoftnet(data string) map[string]int64 {
	got := map[string]int64{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		for i, name := range softnetColumns {
			if i >= len(f) {
				continue
			}
			if n, err := strconv.ParseInt(f[i], 16, 64); err == nil {
				got[name] += n
			}
		}
	}
	return got
}

// increases returns the counters that are larger in b than in a, less their value in a.
func increases(a, b map[string]int64) map[string]int64 {
	d := map[string]int64{}
	for k, v1 := range b {
		if v0, ok := a[k]; ok && v1 > v0 {
			d[k] = v1 - v0
		}
	}
	return d
}
