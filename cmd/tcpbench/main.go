// Command tcpbench measures inner TCP over the netstack tunnel driver with SoftPSP.
// The agent prints one JSON line that "perfrig run -workload exec" reads, for example:
//
//	perfrig run -workload exec -name netstack-bbr -ready tcp:4433 -delay 10ms -loss 0.1 -omit 5s -duration 30s \
//	  -server-argv '["tcpbench","relay","-listen","$SERVER_IP","-peer","$CLIENT_IP"]' \
//	  -client-argv '["tcpbench","agent","-relay","$SERVER_IP","-bind","$CLIENT_IP","-cc","bbr","-streams","$STREAMS","-omit","${OMIT_S}s","-duration","${DURATION_S}s"]'
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apoxy-dev/icx"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/api"
)

const (
	tunnelPort = 6081
	ctlPort    = 4433
	sinkPort   = 5201
	echoPort   = 7
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
	fmt.Fprintln(os.Stderr, "usage: tcpbench agent -relay IP -bind IP [flags] | tcpbench relay -listen IP -peer IP [flags]")
	os.Exit(2)
}

func agentCmd(ctx context.Context, args []string) error {
	o := agentOptions{MTU: icx.MTU(api.TunnelPathMTU)}
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	relay := fs.String("relay", "", "outer IPv4 address of the relay")
	bind := fs.String("bind", "", "outer IPv4 address of the agent")
	fs.StringVar(&o.CC, "cc", "bbr", "TCP congestion control of the netstack: bbr, cubic or reno")
	fs.IntVar(&o.Streams, "streams", 1, "parallel TCP flows")
	fs.DurationVar(&o.Duration, "duration", 30*time.Second, "measured run length")
	fs.DurationVar(&o.Omit, "omit", 2*time.Second, "warm-up time of the flows before the measurement")
	fs.DurationVar(&o.Idle, "idle", time.Second, "RTT probe time before the flows start")
	fs.DurationVar(&o.ProbeInterval, "probe-interval", 10*time.Millisecond, "RTT probe interval")
	fs.IntVar(&o.MTU, "mtu", o.MTU, "inner MTU")
	_ = fs.Parse(args)

	var err error
	if o.Local, o.Peer, err = outerAddrs(*bind, *relay); err != nil {
		return err
	}
	o.Ctl = netip.AddrPortFrom(o.Peer.Addr(), ctlPort).String()
	if o.Streams < 1 || o.Duration <= 0 || o.ProbeInterval <= 0 {
		return errors.New("bad -streams, -duration or -probe-interval")
	}
	res, err := runAgent(ctx, o)
	if err != nil {
		return err
	}
	slog.Info("Run done", "cc", res.CC, "gbps", res.BitsPerSecond/1e9, "retrans_percent", res.RetransPercent,
		"idle_rtt_p50_ms", res.IdleRTT.P50, "load_rtt_p50_ms", res.LoadRTT.P50, "load_rtt_p99_ms", res.LoadRTT.P99)
	return json.NewEncoder(os.Stdout).Encode(res)
}

func relayCmd(ctx context.Context, args []string) error {
	o := relayOptions{MTU: icx.MTU(api.TunnelPathMTU)}
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	listen := fs.String("listen", "", "outer IPv4 address of the relay")
	peer := fs.String("peer", "", "outer IPv4 address of the agent")
	fs.IntVar(&o.MTU, "mtu", o.MTU, "inner MTU")
	_ = fs.Parse(args)

	var err error
	if o.Local, o.Peer, err = outerAddrs(*listen, *peer); err != nil {
		return err
	}
	ln, err := net.Listen("tcp4", netip.AddrPortFrom(o.Local.Addr(), ctlPort).String())
	if err != nil {
		return err
	}
	defer ln.Close()
	total, err := runRelay(ctx, o, ln)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(total)
}

// outerAddrs returns the tunnel addresses of the local and the peer side.
func outerAddrs(local, peer string) (netip.AddrPort, netip.AddrPort, error) {
	l, err := netip.ParseAddr(local)
	if err != nil || !l.Is4() {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("bad local address %q: want IPv4", local)
	}
	p, err := netip.ParseAddr(peer)
	if err != nil || !p.Is4() {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("bad peer address %q: want IPv4", peer)
	}
	return netip.AddrPortFrom(l, tunnelPort), netip.AddrPortFrom(p, tunnelPort), nil
}
