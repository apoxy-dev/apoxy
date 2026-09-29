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
