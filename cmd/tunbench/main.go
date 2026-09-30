// Command tunbench measures the cost of carrying tunnel packets from an agent
// to a relay over one raw UDP socket, with no Envoy and no socket wrappers.
// It has two transports:
//
//   - quic: one packet in each QUIC DATAGRAM frame, with the tunnel's QUIC
//     config. The default build uses the apoxy-dev quic-go fork with congestion
//     control off. Build with "-modfile=stock.mod -tags stock" for stock quic-go.
//   - softpsp: the ICX userspace datapath (Geneve, AES-GCM-128 with PSP keys)
//     with batched UDP reads and writes.
//
// The agent sends packets of the tunnel MTU for -omit plus -duration. The relay
// counts the packets that it decrypts. The agent prints one JSON line with the
// receive rate and the CPU of each side in the measured window, which
// "perfrig run -workload exec" reads:
//
//	perfrig run -workload exec -name quic-fork -ready tcp:4433 -omit 5s -duration 60s \
//	  -server-cmd 'tunbench relay -transport quic' \
//	  -client-cmd 'tunbench agent -transport quic -relay $SERVER_IP:4433 -omit ${OMIT_S}s -duration ${DURATION_S}s'
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/apoxy-dev/icx"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// sockBuf is the UDP socket buffer size that quic-go asks for. All transports use it.
const sockBuf = 7 << 20

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "agent":
		err = agentCmd(ctx, os.Args[2:])
	case "relay":
		err = relayCmd(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		slog.Error("Benchmark failed", "error", err)
		stop()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tunbench agent -relay HOST:PORT [flags] | tunbench relay [flags]")
	os.Exit(2)
}

// options are the flags of both sides.
type options struct {
	Transport string
	Size      int
	Batch     int
	QlogDir   string
	QlogMax   int64

	// Agent only.
	Duration time.Duration
	Omit     time.Duration
	Rate     float64
}

func (o *options) register(fs *flag.FlagSet) {
	fs.StringVar(&o.Transport, "transport", "quic", "quic or softpsp")
	fs.IntVar(&o.Size, "size", icx.MTU(1500), "inner packet size in bytes (default: the tunnel MTU)")
	fs.IntVar(&o.Batch, "batch", 64, "softpsp: packets in each sendmmsg and recvmmsg call")
	fs.StringVar(&o.QlogDir, "qlog-dir", "", "quic: write qlog files to this directory")
	fs.Int64Var(&o.QlogMax, "qlog-max-bytes", 8<<20, "quic: stop writing records to a qlog file after this size")
}

func (o *options) validate() error {
	if o.Transport != "quic" && o.Transport != "softpsp" {
		return fmt.Errorf("unknown transport %q: want quic or softpsp", o.Transport)
	}
	if o.Size < header.IPv4MinimumSize+header.UDPMinimumSize || o.Size > 9000 {
		return fmt.Errorf("bad -size %d: want 28 to 9000", o.Size)
	}
	if o.Batch < 1 {
		return fmt.Errorf("bad -batch %d: want 1 or more", o.Batch)
	}
	if o.QlogDir != "" {
		return os.MkdirAll(o.QlogDir, 0o755)
	}
	return nil
}

// transportName names the transport in results and qlog files.
func transportName(transport string) string {
	if transport == "quic" {
		return "quic-" + quicBuild
	}
	return transport
}

func agentCmd(ctx context.Context, args []string) error {
	var o options
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	o.register(fs)
	relay := fs.String("relay", "", "relay address, HOST:PORT (TCP control and UDP data)")
	fs.DurationVar(&o.Duration, "duration", 30*time.Second, "measured run length")
	fs.DurationVar(&o.Omit, "omit", 2*time.Second, "warm-up time before the measurement")
	rate := fs.String("rate", "0", "inner bit rate, for example 2G (0: send as fast as possible)")
	_ = fs.Parse(args)

	var err error
	if o.Rate, err = parseRate(*rate); err != nil {
		return err
	}
	if *relay == "" {
		return errors.New("the agent needs -relay")
	}
	if err := o.validate(); err != nil {
		return err
	}
	res, err := runAgent(ctx, o, *relay)
	if err != nil {
		return err
	}
	slog.Info("Run done", "transport", res.Transport, "gbps", res.BitsPerSecond/1e9,
		"lost_percent", res.LostPercent, "agent_cores_per_gbps", res.AgentCoresPerGbps,
		"relay_cores_per_gbps", res.RelayCoresPerGbps)
	return json.NewEncoder(os.Stdout).Encode(res)
}

func relayCmd(ctx context.Context, args []string) error {
	var o options
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	o.register(fs)
	listen := fs.String("listen", "0.0.0.0:4433", "TCP control and UDP data address")
	_ = fs.Parse(args)
	if err := o.validate(); err != nil {
		return err
	}

	ln, err := net.Listen("tcp4", *listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	conn, err := listenUDP(*listen)
	if err != nil {
		return err
	}
	defer conn.Close()

	slog.Info("Relay listening", "addr", *listen, "transport", transportName(o.Transport))
	total, err := runRelay(ctx, o, ln, conn)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Transport string `json:"transport"`
		mark
	}{transportName(o.Transport), total})
}

// listenUDP opens a raw IPv4 UDP socket.
func listenUDP(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", a)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(c.SetReadBuffer(sockBuf), c.SetWriteBuffer(sockBuf)); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// sender sends packets of the agent.
type sender interface {
	// send sends a burst of packets and returns how many it sent.
	send() (int, error)
	Close() error
}

// mark is a snapshot of the counters and the CPU time of one side.
type mark struct {
	Packets uint64  `json:"packets"`
	Bytes   uint64  `json:"bytes"`
	Nanos   int64   `json:"nanos"`
	CPU     float64 `json:"cpu_s"`
}

// counter counts the packets that the relay receives.
type counter struct {
	packets, bytes atomic.Uint64
}

func (c *counter) add(packets, bytes uint64) {
	c.packets.Add(packets)
	c.bytes.Add(bytes)
}

func (c *counter) mark(start time.Time) mark {
	return mark{
		Packets: c.packets.Load(),
		Bytes:   c.bytes.Load(),
		Nanos:   time.Since(start).Nanoseconds(),
		CPU:     cpuSeconds(),
	}
}

// cpuSeconds returns the user and system CPU time of this process.
func cpuSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()).Seconds()
}

// runAgent sends packets to the relay and asks the relay for its counters at
// the start and at the end of the measured window.
func runAgent(ctx context.Context, o options, relay string) (result, error) {
	raddr, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		return result{}, err
	}
	var d net.Dialer
	ctl, err := d.DialContext(ctx, "tcp4", relay)
	if err != nil {
		return result{}, fmt.Errorf("connect to the relay control port: %w", err)
	}
	defer ctl.Close()
	conn, err := listenUDP("0.0.0.0:0")
	if err != nil {
		return result{}, err
	}
	defer conn.Close()

	pkt := innerPacket(o.Size)
	var s sender
	if o.Transport == "quic" {
		s, err = dialQUIC(ctx, o, conn, raddr, pkt)
	} else {
		s, err = newSoftPSPSender(conn, raddr, pkt, o.Batch)
	}
	if err != nil {
		return result{}, err
	}
	defer s.Close()

	start := time.Now()
	var sent atomic.Uint64
	sendCtx, stopSend := context.WithCancel(ctx)
	defer stopSend()
	done := make(chan error, 1)
	go func() { done <- sendLoop(sendCtx, s, newPacer(o.Rate, o.Size, start), &sent) }()

	r := bufio.NewReader(ctl)
	var agent, relayMarks [2]mark
	for i, wait := range []time.Duration{o.Omit, o.Duration} {
		if err := sleep(ctx, wait, done); err != nil {
			return result{}, err
		}
		n := sent.Load()
		agent[i] = mark{Packets: n, Bytes: n * uint64(o.Size), Nanos: time.Since(start).Nanoseconds(), CPU: cpuSeconds()}
		if relayMarks[i], err = askMark(ctl, r); err != nil {
			return result{}, err
		}
	}
	stopSend()
	s.Close()
	if err := <-done; err != nil {
		return result{}, err
	}
	return newResult(transportName(o.Transport), o.Size, agent, relayMarks), nil
}

// sleep waits for d. It returns early when ctx ends or the sender stops.
func sleep(ctx context.Context, d time.Duration, done <-chan error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err == nil {
			err = errors.New("the sender stopped before the end of the run")
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

// sendLoop calls s.send until ctx ends.
func sendLoop(ctx context.Context, s sender, p pacer, sent *atomic.Uint64) error {
	for ctx.Err() == nil {
		// Sleep only when more than 1 ms ahead, so a paced sender sends in bursts.
		if d := p.wait(sent.Load(), time.Now()); d > time.Millisecond {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(d):
			}
		}
		n, err := s.send()
		sent.Add(uint64(n))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	return nil
}

// pacer spaces packets to keep a bit rate. A zero pacer does not wait.
type pacer struct {
	start     time.Time
	perPacket float64 // nanoseconds
}

func newPacer(rate float64, size int, start time.Time) pacer {
	if rate <= 0 {
		return pacer{}
	}
	return pacer{start: start, perPacket: float64(size) * 8 / rate * 1e9}
}

// wait returns how long to wait until packet number sent is due.
func (p pacer) wait(sent uint64, now time.Time) time.Duration {
	if p.perPacket == 0 {
		return 0
	}
	return p.start.Add(time.Duration(float64(sent) * p.perPacket)).Sub(now)
}

// parseRate reads a bit rate such as "0", "800M", "2G" or "1.5e9".
func parseRate(s string) (float64, error) {
	num, mult := s, 1.0
	if n := len(s); n > 0 {
		switch strings.ToUpper(s[n-1:]) {
		case "K":
			num, mult = s[:n-1], 1e3
		case "M":
			num, mult = s[:n-1], 1e6
		case "G":
			num, mult = s[:n-1], 1e9
		}
	}
	v, err := strconv.ParseFloat(num, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("bad rate %q: want bits per second, for example 2G", s)
	}
	return v * mult, nil
}

// runRelay serves one agent. It counts the received packets until the agent
// closes the control connection, and returns the last counters.
func runRelay(ctx context.Context, o options, ln net.Listener, conn *net.UDPConn) (mark, error) {
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Close the sockets when ctx ends, to stop Accept and the receive loop.
	defer context.AfterFunc(ctx, func() {
		ln.Close()
		conn.Close()
	})()

	ctl, err := ln.Accept()
	if err != nil {
		return mark{}, fmt.Errorf("accept control connection: %w", err)
	}
	defer ctl.Close()

	var c counter
	done := make(chan error, 1)
	go func() {
		if o.Transport == "quic" {
			done <- receiveQUIC(ctx, o, conn, &c)
			return
		}
		// The relay only receives, so the port of the peer is not used.
		peer := &net.UDPAddr{IP: ctl.RemoteAddr().(*net.TCPAddr).IP}
		done <- receiveSoftPSP(ctx, conn, peer, o, &c)
	}()

	err = serveMarks(ctl, &c, start)
	total := c.mark(start)
	cancel()
	return total, errors.Join(err, <-done)
}

// serveMarks answers each "mark" line of the agent with the relay counters.
func serveMarks(ctl net.Conn, c *counter, start time.Time) error {
	sc := bufio.NewScanner(ctl)
	enc := json.NewEncoder(ctl)
	for sc.Scan() {
		if sc.Text() != "mark" {
			return fmt.Errorf("unknown control message %q", sc.Text())
		}
		if err := enc.Encode(c.mark(start)); err != nil {
			return err
		}
	}
	return sc.Err()
}

// result is the JSON line of the agent. The first fields are what perfrig reads.
type result struct {
	Seconds           float64 `json:"seconds"`
	BitsPerSecond     float64 `json:"bits_per_second"`
	PacketsPerSecond  float64 `json:"packets_per_second"`
	LostPercent       float64 `json:"lost_percent"`
	SentBitsPerSecond float64 `json:"sent_bits_per_second"`
	Transport         string  `json:"transport"`
	Size              int     `json:"size"`
	// Cores are CPU seconds per second of each process in the measured window.
	AgentCores        float64 `json:"agent_cores"`
	RelayCores        float64 `json:"relay_cores"`
	AgentCoresPerGbps float64 `json:"agent_cores_per_gbps"`
	RelayCoresPerGbps float64 `json:"relay_cores_per_gbps"`
}

// newResult computes the rates from the marks at the start and at the end of
// the window. CPU per Gbps uses the received rate for both sides.
func newResult(transport string, size int, agent, relay [2]mark) result {
	r := result{Transport: transport, Size: size}
	if s := time.Duration(relay[1].Nanos - relay[0].Nanos).Seconds(); s > 0 {
		r.Seconds = s
		r.BitsPerSecond = float64(relay[1].Bytes-relay[0].Bytes) * 8 / s
		r.PacketsPerSecond = float64(relay[1].Packets-relay[0].Packets) / s
		r.RelayCores = (relay[1].CPU - relay[0].CPU) / s
	}
	if s := time.Duration(agent[1].Nanos - agent[0].Nanos).Seconds(); s > 0 {
		r.SentBitsPerSecond = float64(agent[1].Bytes-agent[0].Bytes) * 8 / s
		r.AgentCores = (agent[1].CPU - agent[0].CPU) / s
	}
	sent, got := agent[1].Packets-agent[0].Packets, relay[1].Packets-relay[0].Packets
	if sent > got {
		r.LostPercent = 100 * float64(sent-got) / float64(sent)
	}
	if gbps := r.BitsPerSecond / 1e9; gbps > 0 {
		r.AgentCoresPerGbps = r.AgentCores / gbps
		r.RelayCoresPerGbps = r.RelayCores / gbps
	}
	return r
}
