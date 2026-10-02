package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// userHZ is the /proc/stat tick rate. Linux uses 100 on all supported arches.
const userHZ = 100

// cpuTimes are busy CPU seconds of all CPUs from the "cpu" line of /proc/stat.
type cpuTimes struct {
	User, System, IRQ float64
}

func (t cpuTimes) total() float64 { return t.User + t.System + t.IRQ }

func readCPUTimes() (cpuTimes, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	return parseProcStat(string(data))
}

// parseProcStat reads "cpu user nice system idle iowait irq softirq ...".
func parseProcStat(data string) (cpuTimes, error) {
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "cpu" {
			continue
		}
		if len(f) < 8 {
			return cpuTimes{}, fmt.Errorf("short cpu line in /proc/stat: %q", line)
		}
		var v [7]float64
		for i := range v {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return cpuTimes{}, fmt.Errorf("bad cpu line in /proc/stat: %q", line)
			}
			v[i] = float64(n) / userHZ
		}
		return cpuTimes{User: v[0] + v[1], System: v[2], IRQ: v[5] + v[6]}, nil
	}
	return cpuTimes{}, errors.New("no cpu line in /proc/stat")
}

// load1 returns the 1-minute load average of the host, or 0.
func load1() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	v, err := parseLoadAvg(string(data))
	if err != nil {
		return 0
	}
	return v
}

// parseLoadAvg reads the first field of /proc/loadavg.
func parseLoadAvg(data string) (float64, error) {
	f := strings.Fields(data)
	if len(f) == 0 {
		return 0, errors.New("empty /proc/loadavg")
	}
	return strconv.ParseFloat(f[0], 64)
}

var errNoProcess = errors.New("process not in /proc")

// treeCPU returns the user and system seconds of process root and its live
// descendants, with the children that they waited for. It follows parent PIDs,
// so it also finds descendants in other process groups.
func treeCPU(root int) (user, system float64, err error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, err
	}
	stats := map[int]pidStat{}
	children := map[int][]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue // The process exited.
		}
		st, err := parsePIDStat(string(data))
		if err != nil {
			return 0, 0, err
		}
		stats[pid] = st
		children[st.ppid] = append(children[st.ppid], pid)
	}
	if _, ok := stats[root]; !ok {
		return 0, 0, fmt.Errorf("%w: pid %d", errNoProcess, root)
	}
	var utime, stime int64
	for queue := []int{root}; len(queue) > 0; queue = queue[1:] {
		st := stats[queue[0]]
		utime += st.utime + st.cutime
		stime += st.stime + st.cstime
		queue = append(queue, children[queue[0]]...)
	}
	return float64(utime) / userHZ, float64(stime) / userHZ, nil
}

// pidStat holds fields of /proc/PID/stat. Times are in clock ticks.
type pidStat struct {
	ppid                         int
	utime, stime, cutime, cstime int64
}

// parsePIDStat reads "pid (comm) state ppid ... utime stime cutime cstime ...".
// comm can hold spaces and parentheses, so the fields start after the last ')'.
func parsePIDStat(data string) (pidStat, error) {
	i := strings.LastIndexByte(data, ')')
	if i < 0 {
		return pidStat{}, fmt.Errorf("bad /proc/PID/stat: %q", data)
	}
	// f[0] is field 3 (state), so field n is f[n-3].
	f := strings.Fields(data[i+1:])
	if len(f) < 15 {
		return pidStat{}, fmt.Errorf("short /proc/PID/stat: %q", data)
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return pidStat{}, fmt.Errorf("bad ppid in /proc/PID/stat: %q", data)
	}
	var v [4]int64
	for j := range v {
		if v[j], err = strconv.ParseInt(f[11+j], 10, 64); err != nil {
			return pidStat{}, fmt.Errorf("bad times in /proc/PID/stat: %q", data)
		}
	}
	return pidStat{ppid: ppid, utime: v[0], stime: v[1], cutime: v[2], cstime: v[3]}, nil
}

// Socket is a local socket that a server opens.
type Socket struct {
	Proto string // "tcp" or "udp"
	Port  int
}

func (s Socket) String() string { return s.Proto + ":" + strconv.Itoa(s.Port) }

// parseSocket reads "tcp:5201", "udp:4433" or "none".
func parseSocket(s string) (Socket, error) {
	if s == "" || s == "none" {
		return Socket{}, nil
	}
	proto, port, ok := strings.Cut(s, ":")
	if !ok || (proto != "tcp" && proto != "udp") {
		return Socket{}, fmt.Errorf("bad socket %q: want tcp:PORT, udp:PORT or none", s)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return Socket{}, fmt.Errorf("bad port in socket %q", s)
	}
	return Socket{Proto: proto, Port: p}, nil
}

// socketOpen reports whether the netns of pid has the socket. It reads
// /proc/PID/net, which shows the netns of that process.
func socketOpen(pid int, s Socket) bool {
	for _, suffix := range []string{"", "6"} {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s%s", pid, s.Proto, suffix))
		if err == nil && tableHasSocket(string(data), s) {
			return true
		}
	}
	return false
}

// tableHasSocket finds a socket on s.Port in a /proc/net/{tcp,udp}[6] table.
// A TCP socket must be in the LISTEN state (0A).
func tableHasSocket(table string, s Socket) bool {
	lines := strings.Split(table, "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		i := strings.LastIndexByte(f[1], ':')
		if i < 0 {
			continue
		}
		port, err := strconv.ParseUint(f[1][i+1:], 16, 16)
		if err != nil || int(port) != s.Port {
			continue
		}
		if s.Proto == "tcp" && f[3] != "0A" {
			continue
		}
		return true
	}
	return false
}
