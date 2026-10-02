// Command sockbench measures QUIC DATAGRAM throughput over the socket paths
// that the tunnel agent and relay can give quic-go. The server counts the
// datagrams that it gets. The client sends datagrams and prints one JSON line
// that "perfrig run -workload exec" reads. A TCP connection on the same port
// marks the start and the end of the measurement.
//
//	perfrig run -workload exec -name sock-oob -ready tcp:4433 -omit 2s -duration 30s \
//	  -server-argv '["sockbench","server","-path","oob","-listen",":4433"]' \
//	  -client-argv '["sockbench","client","-path","oob","-addr","$SERVER_IP:4433","-omit","${OMIT_S}s","-duration","${DURATION_S}s"]'
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "server":
		err = serverCmd(ctx, os.Args[2:])
	case "client":
		err = clientCmd(ctx, os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "usage: sockbench server [flags] | sockbench client -addr HOST:PORT [flags]")
	os.Exit(2)
}

// opts are the flags of both sides.
type opts struct {
	Path    string
	GSO     bool
	SockBuf int
}

func (o *opts) register(fs *flag.FlagSet) {
	fs.StringVar(&o.Path, "path", pathRaw, "socket path: raw, wrapped, oob or udp (no QUIC)")
	fs.BoolVar(&o.GSO, "gso", true, "let quic-go use GSO (false sets QUIC_GO_DISABLE_GSO); the udp path sends with GSO, or with sendmmsg when false")
	fs.IntVar(&o.SockBuf, "sockbuf", 16<<20, "UDP socket buffer size in bytes, as the agent sets it (0: keep the kernel default)")
}

func (o opts) apply() error {
	switch o.Path {
	case pathRaw, pathWrapped, pathOOB, pathUDP:
	default:
		return fmt.Errorf("unknown path %q: want raw, wrapped, oob or udp", o.Path)
	}
	if !o.GSO {
		// quic-go reads this variable when a Transport starts to use a conn.
		return os.Setenv("QUIC_GO_DISABLE_GSO", "true")
	}
	return nil
}

func serverCmd(ctx context.Context, args []string) error {
	var o opts
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	o.register(fs)
	listen := fs.String("listen", ":4433", "UDP and TCP listen address")
	_ = fs.Parse(args)
	if err := o.apply(); err != nil {
		return err
	}

	uc, err := listenUDP(*listen, o.SockBuf)
	if err != nil {
		return err
	}
	var received, quicDrops atomic.Uint64
	if o.Path == pathUDP {
		defer uc.Close()
		go func() {
			if err := receiveUDP(uc, &received); err != nil && !errors.Is(err, net.ErrClosed) {
				slog.Error("Failed to read UDP", "error", err)
			}
		}()
	} else {
		ln, closeLn, err := listenQUIC(o.Path, uc, &quicDrops)
		if err != nil {
			return err
		}
		defer closeLn()
		go acceptDatagrams(ctx, ln, &received)
	}

	ctl, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer ctl.Close()
	slog.Info("Serving", "path", o.Path, "listen", *listen, "gso", o.GSO, "sockbuf", o.SockBuf)
	return serveControl(ctx, ctl, func() counters {
		return counters{Packets: received.Load(), QUICDrops: quicDrops.Load(), KernelDrops: rcvbufErrors()}
	})
}

// counters are the receive counters of the server.
type counters struct {
	Packets uint64 `json:"packets"`
	// QUICDrops are packets that quic-go dropped, for example because a
	// connection queue was full.
	QUICDrops uint64 `json:"quic_drops"`
	// KernelDrops is the UDP RcvbufErrors count of the server netns.
	KernelDrops uint64 `json:"kernel_drops"`
}

func (c counters) sub(o counters) counters {
	return counters{Packets: c.Packets - o.Packets, QUICDrops: c.QUICDrops - o.QUICDrops, KernelDrops: c.KernelDrops - o.KernelDrops}
}

// report is the server reply to "stop".
type report struct {
	Seconds float64 `json:"seconds"`
	counters
}

// serveControl serves one control connection. "start" and "stop" lines mark
// the measurement, and the reply to "stop" is a report. It returns when the
// client closes the connection.
func serveControl(ctx context.Context, ln net.Listener, snap func() counters) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	c, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("accept control connection: %w", err)
	}
	defer c.Close()
	stopConn := context.AfterFunc(ctx, func() { c.Close() })
	defer stopConn()

	var (
		start time.Time
		from  counters
	)
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		switch cmd := sc.Text(); cmd {
		case "start":
			start, from = time.Now(), snap()
		case "stop":
			if start.IsZero() {
				return errors.New("got stop before start")
			}
			r := report{Seconds: time.Since(start).Seconds(), counters: snap().sub(from)}
			slog.Info("Measured received datagrams", "packets", r.Packets, "seconds", r.Seconds,
				"pps", float64(r.Packets)/r.Seconds, "quic_drops", r.QUICDrops, "kernel_drops", r.KernelDrops)
			if err := json.NewEncoder(c).Encode(r); err != nil {
				return fmt.Errorf("write report: %w", err)
			}
		default:
			return fmt.Errorf("unknown control command %q", cmd)
		}
	}
	return sc.Err()
}

// result is the last stdout line. perfrig reads seconds, bits_per_second,
// packets_per_second and lost_percent. The other fields are for people.
type result struct {
	Seconds              float64 `json:"seconds"`
	BitsPerSecond        float64 `json:"bits_per_second"`
	PacketsPerSecond     float64 `json:"packets_per_second"`
	LostPercent          float64 `json:"lost_percent"`
	SentPacketsPerSecond float64 `json:"sent_packets_per_second"`
	Path                 string  `json:"path"`
	GSO                  bool    `json:"gso"`
	GSOActive            bool    `json:"gso_active"`
	Size                 int     `json:"size"`
	Conns                int     `json:"conns"`
	QUICDrops            uint64  `json:"quic_drops"`
	KernelDrops          uint64  `json:"kernel_drops"`
}

// newResult gives the receive rate from the server report and the send rate
// from the client count. Each datagram carries size bytes of payload.
func newResult(rep report, sent uint64, sentFor time.Duration, size int) result {
	var r result
	r.Seconds = rep.Seconds
	if rep.Seconds > 0 {
		r.PacketsPerSecond = float64(rep.Packets) / rep.Seconds
		r.BitsPerSecond = r.PacketsPerSecond * float64(size) * 8
	}
	if s := sentFor.Seconds(); s > 0 {
		r.SentPacketsPerSecond = float64(sent) / s
	}
	if r.SentPacketsPerSecond > 0 {
		r.LostPercent = max(0, 100*(1-r.PacketsPerSecond/r.SentPacketsPerSecond))
	}
	r.Size = size
	r.QUICDrops, r.KernelDrops = rep.QUICDrops, rep.KernelDrops
	return r
}

// rcvbufErrors returns the UDP RcvbufErrors count of this netns, or 0 when
// /proc/net/snmp is not available.
func rcvbufErrors() uint64 {
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0
	}
	v, _ := snmpValue(string(data), "Udp", "RcvbufErrors")
	return v
}

// snmpValue reads one counter from /proc/net/snmp. Each protocol has a line of
// names and then a line of values.
func snmpValue(data, proto, name string) (uint64, bool) {
	var names []string
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != proto+":" {
			continue
		}
		if names == nil {
			names = f
			continue
		}
		i := slices.Index(names, name)
		if i < 0 || i >= len(f) {
			return 0, false
		}
		v, err := strconv.ParseUint(f[i], 10, 64)
		return v, err == nil
	}
	return 0, false
}

func clientCmd(ctx context.Context, args []string) error {
	var o opts
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	o.register(fs)
	addr := fs.String("addr", "", "server address HOST:PORT")
	size := fs.Int("size", 1285, "datagram payload in bytes (default: 1280 B inner MTU and a 5 B frame header)")
	duration := fs.Duration("duration", 30*time.Second, "measured run length")
	omit := fs.Duration("omit", 2*time.Second, "warm-up before the measurement")
	conns := fs.Int("conns", 1, "QUIC connections on the one socket")
	_ = fs.Parse(args)
	if err := o.apply(); err != nil {
		return err
	}
	if *addr == "" || *size < 1 || *conns < 1 || *duration <= 0 {
		return errors.New("bad flags: need -addr, -size >= 1, -conns >= 1 and -duration > 0")
	}
	raddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		return err
	}
	// The agent binds its one socket to ":0".
	uc, err := listenUDP(":0", o.SockBuf)
	if err != nil {
		return err
	}
	ctl, err := net.Dial("tcp", *addr)
	if err != nil {
		uc.Close()
		return fmt.Errorf("dial control connection: %w", err)
	}
	defer ctl.Close()

	var (
		sent      atomic.Uint64
		gsoActive bool
		cleanup   func()
	)
	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, gctx := errgroup.WithContext(sendCtx)
	if o.Path == pathUDP {
		cleanup = func() { uc.Close() }
		g.Go(func() error { return blastUDP(gctx, uc, raddr, *size, o.GSO, &sent) })
	} else {
		qconns, closeQUIC, err := dialQUIC(ctx, o.Path, uc, raddr, *conns)
		if err != nil {
			return err
		}
		cleanup = closeQUIC
		gsoActive = qconns[0].ConnectionState().GSO
		slog.Info("Connected", "path", o.Path, "conns", len(qconns), "gso", o.GSO, "gso_active", gsoActive)
		warmEnd := time.Now().Add(*omit)
		for _, c := range qconns {
			g.Go(func() error { return sendDatagrams(gctx, c, *size, warmEnd, &sent) })
		}
	}

	rep, sentN, sentFor, err := measure(gctx, ctl, *omit, *duration, sent.Load)
	cancel()
	cleanup()
	if gerr := g.Wait(); gerr != nil {
		return gerr
	}
	if err != nil {
		return err
	}

	res := newResult(rep, sentN, sentFor, *size)
	res.Path, res.GSO, res.GSOActive, res.Conns = o.Path, o.GSO, gsoActive, *conns
	slog.Info("Result", "path", res.Path, "gso", res.GSO, "gso_active", res.GSOActive,
		"pps", res.PacketsPerSecond, "gbps", res.BitsPerSecond/1e9, "sent_pps", res.SentPacketsPerSecond,
		"lost_percent", res.LostPercent, "quic_drops", res.QUICDrops, "kernel_drops", res.KernelDrops)
	return json.NewEncoder(os.Stdout).Encode(res)
}

// measure waits for the warm-up, marks the start, waits for the run and marks
// the end. It returns the server report and the datagrams sent in the run.
func measure(ctx context.Context, ctl net.Conn, omit, duration time.Duration, sent func() uint64) (report, uint64, time.Duration, error) {
	if err := sleep(ctx, omit); err != nil {
		return report{}, 0, 0, err
	}
	if _, err := fmt.Fprintln(ctl, "start"); err != nil {
		return report{}, 0, 0, fmt.Errorf("send start: %w", err)
	}
	t0, s0 := time.Now(), sent()
	if err := sleep(ctx, duration); err != nil {
		return report{}, 0, 0, err
	}
	if _, err := fmt.Fprintln(ctl, "stop"); err != nil {
		return report{}, 0, 0, fmt.Errorf("send stop: %w", err)
	}
	sentFor, sentN := time.Since(t0), sent()-s0
	var rep report
	if err := json.NewDecoder(ctl).Decode(&rep); err != nil {
		return report{}, 0, 0, fmt.Errorf("read report: %w", err)
	}
	return rep, sentN, sentFor, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
