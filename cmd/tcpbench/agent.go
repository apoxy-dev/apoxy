package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/apoxy-dev/icx/psp"

	"github.com/apoxy-dev/apoxy/cmd/internal/bench"
	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

// echoWait is how long the agent waits for the last probe echoes.
const echoWait = time.Second

// agentOptions configure the agent side.
type agentOptions struct {
	Local, Peer   netip.AddrPort
	Ctl           string
	CC            string
	Streams       int
	MTU           int
	Duration      time.Duration
	Omit          time.Duration
	Idle          time.Duration
	ProbeInterval time.Duration
}

// result is the JSON line of the agent. The first fields are what perfrig reads.
type result struct {
	Seconds          float64 `json:"seconds"`
	BitsPerSecond    float64 `json:"bits_per_second"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	Retransmits      uint64  `json:"retransmits"`
	CC               string  `json:"cc"`
	Streams          int     `json:"streams"`
	// RetransPercent is the part of the received data segments that are retransmissions.
	RetransPercent float64 `json:"retrans_percent"`
	// IdleRTT is the probe RTT before the flows start. LoadRTT is the probe RTT in the measured window.
	IdleRTT bench.RTTStats `json:"idle_rtt_ms"`
	LoadRTT bench.RTTStats `json:"load_rtt_ms"`
	// Cores are CPU seconds per second of each process in the measured window.
	AgentCores        float64 `json:"agent_cores"`
	RelayCores        float64 `json:"relay_cores"`
	AgentCoresPerGbps float64 `json:"agent_cores_per_gbps"`
	RelayCoresPerGbps float64 `json:"relay_cores_per_gbps"`
}

// runAgent runs the flows through the netstack driver and asks the relay for its
// counters at the start and at the end of the measured window.
func runAgent(ctx context.Context, o agentOptions) (result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var d net.Dialer
	ctl, err := d.DialContext(ctx, "tcp4", o.Ctl)
	if err != nil {
		return result{}, fmt.Errorf("connect to the relay control port: %w", err)
	}
	defer ctl.Close()
	r := bufio.NewReader(ctl)
	// The relay answers the first mark when its datapath runs.
	if _, err := askMark(ctl, r); err != nil {
		return result{}, err
	}

	netstack.TCPCongestionControl = o.CC
	phy, err := listenPhy(o.Local)
	if err != nil {
		return result{}, err
	}
	defer phy.Close()
	engine, err := newEngine(o.Local, o.Peer, psp.Initiator)
	if err != nil {
		return result{}, err
	}
	ns, err := netstack.NewICXNetwork(engine, phy, o.MTU, nil, "")
	if err != nil {
		return result{}, err
	}
	defer ns.Close()
	if err := ns.AddAddr(netip.PrefixFrom(agentInner, 32)); err != nil {
		return result{}, err
	}
	go func() {
		if err := ns.Start(ctx); err != nil {
			slog.Error("Agent datapath stopped", "error", err)
		}
	}()

	start := time.Now()
	echo, err := ns.DialContext(ctx, "udp", netip.AddrPortFrom(relayInner, echoPort).String())
	if err != nil {
		return result{}, err
	}
	defer echo.Close()
	// The flows and the probes stop before the datapath, so late echoes still arrive.
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	p := bench.NewProber(echo, start, o.ProbeInterval, o.Idle+o.Omit+o.Duration)
	go p.Receive()
	go p.Send(runCtx, o.ProbeInterval)
	if err := bench.Sleep(ctx, o.Idle, nil); err != nil {
		return result{}, err
	}
	idleEnd := time.Since(start)

	done := make(chan error, o.Streams)
	var wg sync.WaitGroup
	sink := netip.AddrPortFrom(relayInner, sinkPort).String()
	for range o.Streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done <- flow(runCtx, ns, sink)
		}()
	}
	go func() {
		wg.Wait()
		close(done)
	}()

	var agent, relay [2]mark
	var window [2]time.Duration
	for i, wait := range []time.Duration{o.Omit, o.Duration} {
		if err := bench.Sleep(ctx, wait, done); err != nil {
			return result{}, err
		}
		window[i] = time.Since(start)
		agent[i] = mark{Nanos: window[i].Nanoseconds(), CPU: bench.CPUSeconds()}
		if relay[i], err = askMark(ctl, r); err != nil {
			return result{}, err
		}
	}
	stopRun()
	for err := range done {
		if err != nil {
			return result{}, err
		}
	}
	if err := bench.Sleep(ctx, echoWait, nil); err != nil {
		return result{}, err
	}

	res := newResult(o, agent, relay)
	res.IdleRTT = bench.NewRTTStats(p.Window(0, idleEnd))
	res.LoadRTT = bench.NewRTTStats(p.Window(window[0], window[1]))
	return res, nil
}

// flow writes to one TCP connection until ctx ends.
func flow(ctx context.Context, ns *netstack.ICXNetwork, addr string) error {
	c, err := ns.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer context.AfterFunc(ctx, func() { c.Close() })()
	buf := make([]byte, 1<<20)
	for {
		if _, err := c.Write(buf); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("write: %w", err)
		}
	}
}

func askMark(ctl net.Conn, r *bufio.Reader) (mark, error) {
	var m mark
	if _, err := io.WriteString(ctl, "mark\n"); err != nil {
		return m, fmt.Errorf("send mark to the relay: %w", err)
	}
	line, err := r.ReadBytes('\n')
	if err != nil {
		return m, fmt.Errorf("read mark from the relay: %w", err)
	}
	if err := json.Unmarshal(line, &m); err != nil {
		return m, fmt.Errorf("parse relay mark %q: %w", line, err)
	}
	return m, nil
}

// newResult computes the rates from the marks at the start and at the end of the window.
func newResult(o agentOptions, agent, relay [2]mark) result {
	r := result{CC: o.CC, Streams: o.Streams}
	s := time.Duration(relay[1].Nanos - relay[0].Nanos).Seconds()
	if s <= 0 {
		return r
	}
	segs := relay[1].Segments - relay[0].Segments
	r.Seconds = s
	r.BitsPerSecond = float64(relay[1].Bytes-relay[0].Bytes) * 8 / s
	r.PacketsPerSecond = float64(segs) / s
	r.Retransmits = relay[1].Retrans - relay[0].Retrans
	if segs > 0 {
		r.RetransPercent = float64(r.Retransmits) * 100 / float64(segs)
	}
	r.RelayCores = (relay[1].CPU - relay[0].CPU) / s
	if as := time.Duration(agent[1].Nanos - agent[0].Nanos).Seconds(); as > 0 {
		r.AgentCores = (agent[1].CPU - agent[0].CPU) / as
	}
	if gbps := r.BitsPerSecond / 1e9; gbps > 0 {
		r.AgentCoresPerGbps = r.AgentCores / gbps
		r.RelayCoresPerGbps = r.RelayCores / gbps
	}
	return r
}
