package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/apoxy-dev/icx/psp"

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
	IdleRTT rttStats `json:"idle_rtt_ms"`
	LoadRTT rttStats `json:"load_rtt_ms"`
	// Cores are CPU seconds per second of each process in the measured window.
	AgentCores        float64 `json:"agent_cores"`
	RelayCores        float64 `json:"relay_cores"`
	AgentCoresPerGbps float64 `json:"agent_cores_per_gbps"`
	RelayCoresPerGbps float64 `json:"relay_cores_per_gbps"`
}

// rttStats are the RTT percentiles of the echoed probes, in milliseconds.
type rttStats struct {
	Probes int     `json:"probes"`
	Lost   int     `json:"lost"`
	P50    float64 `json:"p50"`
	P90    float64 `json:"p90"`
	P99    float64 `json:"p99"`
	Max    float64 `json:"max"`
}

func newRTTStats(rtts []time.Duration, lost int) rttStats {
	st := rttStats{Probes: len(rtts) + lost, Lost: lost}
	if len(rtts) == 0 {
		return st
	}
	slices.Sort(rtts)
	ms := func(q float64) float64 {
		i := int(math.Ceil(q*float64(len(rtts)))) - 1
		return float64(rtts[max(i, 0)]) / float64(time.Millisecond)
	}
	st.P50, st.P90, st.P99, st.Max = ms(0.5), ms(0.9), ms(0.99), ms(1)
	return st
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
	p := newProber(echo, start, o.ProbeInterval, o.Idle+o.Omit+o.Duration)
	go p.receive()
	go p.send(runCtx, o.ProbeInterval)
	if err := sleep(ctx, o.Idle, nil); err != nil {
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
		if err := sleep(ctx, wait, done); err != nil {
			return result{}, err
		}
		window[i] = time.Since(start)
		agent[i] = mark{Nanos: window[i].Nanoseconds(), CPU: cpuSeconds()}
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
	if err := sleep(ctx, echoWait, nil); err != nil {
		return result{}, err
	}

	res := newResult(o, agent, relay)
	res.IdleRTT = newRTTStats(p.window(0, idleEnd))
	res.LoadRTT = newRTTStats(p.window(window[0], window[1]))
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

// sleep waits for d. It returns early when ctx ends or a flow stops.
func sleep(ctx context.Context, d time.Duration, done <-chan error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err == nil {
			err = errors.New("a flow stopped before the end of the run")
		}
		return err
	case <-time.After(d):
		return nil
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

// prober sends numbered UDP probes through the tunnel and records the RTT of each echo.
type prober struct {
	conn  net.Conn
	start time.Time

	mu   sync.Mutex
	sent []time.Duration // Send time by sequence number.
	rtt  []time.Duration // RTT by sequence number, 0 until the echo arrives.
}

func newProber(conn net.Conn, start time.Time, interval, run time.Duration) *prober {
	n := int(run/interval) + 64
	return &prober{conn: conn, start: start, sent: make([]time.Duration, 0, n), rtt: make([]time.Duration, 0, n)}
}

func (p *prober) send(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var b [16]byte
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Since(p.start)
		p.mu.Lock()
		seq := len(p.sent)
		p.sent = append(p.sent, now)
		p.rtt = append(p.rtt, 0)
		p.mu.Unlock()
		binary.BigEndian.PutUint64(b[:8], uint64(seq))
		binary.BigEndian.PutUint64(b[8:], uint64(now))
		if _, err := p.conn.Write(b[:]); err != nil && ctx.Err() == nil {
			slog.Warn("Failed to send RTT probe", "error", err)
		}
	}
}

func (p *prober) receive() {
	var b [64]byte
	for {
		n, err := p.conn.Read(b[:])
		if err != nil {
			return
		}
		if n < 16 {
			continue
		}
		seq := binary.BigEndian.Uint64(b[:8])
		rtt := time.Since(p.start) - time.Duration(binary.BigEndian.Uint64(b[8:16]))
		p.mu.Lock()
		if seq < uint64(len(p.rtt)) {
			p.rtt[seq] = rtt
		}
		p.mu.Unlock()
	}
}

// window returns the RTTs of the probes sent in [from, to) and the number of them with no echo.
func (p *prober) window(from, to time.Duration) ([]time.Duration, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var rtts []time.Duration
	lost := 0
	for i, s := range p.sent {
		if s < from || s >= to {
			continue
		}
		if p.rtt[i] > 0 {
			rtts = append(rtts, p.rtt[i])
		} else {
			lost++
		}
	}
	return rtts, lost
}
