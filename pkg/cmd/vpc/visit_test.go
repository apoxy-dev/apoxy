package vpc

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/dpeckett/network/nettest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/things-go/go-socks5/statute"
	"golang.org/x/net/proxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/apoxy-dev/apoxy/pkg/socksproxy"
)

// TestVisitNetwork checks the sources of SOCKS5 CONNECT, UDP ASSOCIATE and DNS
// through the netstack: the visit source in a visited slot, else the primary.
func TestVisitNetwork(t *testing.T) {
	primary := netip.MustParseAddr("fd61:706f:7879:12:3400:200::1")
	visit := netip.MustParseAddr("fd61:706f:7879:12:3400:100::1")
	slot := netip.MustParsePrefix("fd61:706f:7879:12:3400:100::/88")
	inSlot, outside := netip.MustParseAddr("fd61:706f:7879:12:3400:100::9"), netip.MustParseAddr("fd61:706f:7879:12:3400:300::9")
	dnsAddr := netip.MustParseAddr("fd61:706f:7879:12:3400:100::53")
	// name is in the visited slot, and local is a VPC name of a host address.
	const name, local = "web.vpc.test.", "local.vpc.test."
	loop := netip.MustParseAddr("127.0.0.1")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client := newTestStack(t, primary, visit)
	require.Nil(t, client.SetAddressLifetimes(client.NICID, tcpip.AddrFromSlice(visit.AsSlice()), stack.AddressLifetimes{Deprecated: true}))
	server := newTestStack(t, inSlot, outside, dnsAddr)
	splice(ctx, client, server)
	serveSource(t, server, inSlot, outside)
	queries := serveDNS(t, server, dnsAddr, map[string]netip.Addr{name: inSlot, local: loop})
	host, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop.AsSlice()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = host.Close() })
	go echoSource(host)
	localDst := net.JoinHostPort(local, strconv.Itoa(host.LocalAddr().(*net.UDPAddr).Port))

	out := newVisitNetwork(client.Stack, client.NICID, &network.ResolveConfig{Nameservers: []string{dnsAddr.String()}})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	srv := socksproxy.NewServer(addr, out, network.Host())
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	socks, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	require.NoError(t, err)

	steps := []struct {
		name   string
		visits map[netip.Prefix]netip.Addr
		want   map[netip.Addr]netip.Addr // It maps each destination to its source.
	}{
		{name: "visit", visits: map[netip.Prefix]netip.Addr{slot: visit}, want: map[netip.Addr]netip.Addr{inSlot: visit, outside: primary}},
		{name: "no visit", visits: map[netip.Prefix]netip.Addr{}, want: map[netip.Addr]netip.Addr{inSlot: primary, outside: primary}},
	}
	for _, st := range steps {
		out.setVisits(st.visits)
		for dst, want := range st.want {
			require.Equal(t, want, connectSource(t, socks, net.JoinHostPort(dst.String(), "80")), "%s: CONNECT to %s", st.name, dst)
			require.Equal(t, want, associateSource(t, addr, net.JoinHostPort(dst.String(), "7")), "%s: UDP ASSOCIATE to %s", st.name, dst)
		}
		require.Equal(t, st.want[inSlot], associateSource(t, addr, net.JoinHostPort(name, "7")), "%s: UDP ASSOCIATE to the name", st.name)
		require.Equal(t, loop, associateSource(t, addr, localDst), "%s: UDP ASSOCIATE to a name of a host address", st.name)
		queries.take()
		require.Equal(t, st.want[inSlot], connectSource(t, socks, net.JoinHostPort(name, "80")), "%s: CONNECT to the name", st.name)
		srcs := queries.take()
		require.NotEmpty(t, srcs, st.name)
		for _, src := range srcs {
			require.Equal(t, st.want[inSlot], src, "%s: source of a DNS query", st.name)
		}
	}
}

// splice copies the packets between a and b until ctx ends. It reads again
// every 10 ms, because a read of nettest can miss the notice of a new packet.
func splice(ctx context.Context, a, b *nettest.Stack) {
	cp := func(dst, src *nettest.Stack) {
		for ctx.Err() == nil {
			rctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
			p, err := src.ReadPacket(rctx)
			cancel()
			if err == nil {
				_, _ = dst.WritePacket(p)
			}
		}
	}
	go cp(a, b)
	go cp(b, a)
}

func newTestStack(t *testing.T, addr netip.Addr, more ...netip.Addr) *nettest.Stack {
	t.Helper()
	s, err := nettest.NewStack(addr, "")
	require.NoError(t, err)
	t.Cleanup(s.Close)
	for _, a := range more {
		pa := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}
		require.Nil(t, s.AddProtocolAddress(s.NICID, pa, stack.AddressProperties{}))
	}
	return s
}

// serveSource answers TCP on port 80 (with a newline) and UDP on port 7 of each
// address with the source address of the peer.
func serveSource(t *testing.T, s *nettest.Stack, addrs ...netip.Addr) {
	t.Helper()
	l, err := gonet.ListenTCP(s.Stack, tcpip.FullAddress{NIC: s.NICID, Port: 80}, ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, c.RemoteAddr().String()+"\n")
			_ = c.Close()
		}
	}()
	for _, a := range addrs {
		pc, err := gonet.DialUDP(s.Stack, &tcpip.FullAddress{NIC: s.NICID, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: 7}, nil, ipv6.ProtocolNumber)
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		go echoSource(pc)
	}
}

// echoSource answers each datagram on pc with the source address of the peer.
func echoSource(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte(from.String()), from)
	}
}

// dnsSources has the source addresses of the DNS queries.
type dnsSources struct {
	mu   sync.Mutex
	srcs []netip.Addr
}

// take returns the sources since the last take.
func (d *dnsSources) take() []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	srcs := d.srcs
	d.srcs = nil
	return srcs
}

// serveDNS answers on addr port 53 with the address of each name in names.
func serveDNS(t *testing.T, s *nettest.Stack, addr netip.Addr, names map[string]netip.Addr) *dnsSources {
	t.Helper()
	pc, err := gonet.DialUDP(s.Stack, &tcpip.FullAddress{NIC: s.NICID, Addr: tcpip.AddrFromSlice(addr.AsSlice()), Port: 53}, nil, ipv6.ProtocolNumber)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	d := &dnsSources{}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil || len(q.Question) != 1 {
				continue
			}
			d.mu.Lock()
			d.srcs = append(d.srcs, from.(*net.UDPAddr).AddrPort().Addr())
			d.mu.Unlock()
			r := new(dns.Msg)
			r.SetReply(q)
			qn := q.Question[0]
			target, ok := names[qn.Name]
			hdr := dns.RR_Header{Name: qn.Name, Rrtype: qn.Qtype, Class: dns.ClassINET, Ttl: 60}
			switch {
			case !ok:
				r.Rcode = dns.RcodeNameError
			case qn.Qtype == dns.TypeAAAA && target.Is6():
				r.Answer = append(r.Answer, &dns.AAAA{Hdr: hdr, AAAA: target.AsSlice()})
			case qn.Qtype == dns.TypeA && target.Is4():
				r.Answer = append(r.Answer, &dns.A{Hdr: hdr, A: target.AsSlice()})
			}
			if b, err := r.Pack(); err == nil {
				_, _ = pc.WriteTo(b, from)
			}
		}
	}()
	return d
}

// connectSource dials addr through the SOCKS5 proxy and returns the source
// address that the server saw.
func connectSource(t *testing.T, socks proxy.Dialer, addr string) netip.Addr {
	t.Helper()
	c, err := socks.Dial("tcp", addr)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	// The proxy does not close the client side when the server closes, so the
	// answer ends with a newline.
	line, err := bufio.NewReader(c).ReadString('\n')
	require.NoError(t, err)
	ap, err := netip.ParseAddrPort(strings.TrimSpace(line))
	require.NoError(t, err)
	return ap.Addr()
}

// associateSource sends one datagram to dst with a UDP ASSOCIATE of the proxy at
// addr, and returns the source address that the server saw.
func associateSource(t *testing.T, addr, dst string) netip.Addr {
	t.Helper()
	ctl, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer ctl.Close()
	require.NoError(t, ctl.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = ctl.Write(statute.NewMethodRequest(statute.VersionSocks5, []byte{statute.MethodNoAuth}).Bytes())
	require.NoError(t, err)
	_, err = statute.ParseMethodReply(ctl)
	require.NoError(t, err)
	req := statute.Request{Version: statute.VersionSocks5, Command: statute.CommandAssociate,
		DstAddr: statute.AddrSpec{IP: net.IPv4zero, AddrType: statute.ATYPIPv4}}
	_, err = ctl.Write(req.Bytes())
	require.NoError(t, err)
	rep, err := statute.ParseReply(ctl)
	require.NoError(t, err)
	require.Equal(t, statute.RepSuccess, rep.Response)

	u, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rep.BndAddr.Port})
	require.NoError(t, err)
	defer u.Close()
	require.NoError(t, u.SetDeadline(time.Now().Add(10*time.Second)))
	dg, err := statute.NewDatagram(dst, []byte("source?"))
	require.NoError(t, err)
	_, err = u.Write(dg.Bytes())
	require.NoError(t, err)
	buf := make([]byte, 1500)
	n, err := u.Read(buf)
	require.NoError(t, err)
	got, err := statute.ParseDatagram(buf[:n])
	require.NoError(t, err)
	ap, err := netip.ParseAddrPort(string(got.Data))
	require.NoError(t, err)
	return ap.Addr()
}
