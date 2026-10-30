package socksproxy_test

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/things-go/go-socks5/statute"

	"github.com/apoxy-dev/apoxy/pkg/socksproxy"
)

// fakeNet records dials and resolves names from a table. Each dial goes to a
// local UDP socket that answers with the name of the network.
type fakeNet struct {
	name   string
	names  map[string]string
	echo   string
	fault  fault
	closes atomic.Int32

	mu    sync.Mutex
	dials []string
}

func newFakeNet(t *testing.T, name string, names map[string]string) *fakeNet {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo([]byte(name), from)
		}
	}()
	return &fakeNet{name: name, names: names, echo: pc.LocalAddr().String()}
}

func (f *fakeNet) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, network+" "+addr)
	f.mu.Unlock()
	var d net.Dialer
	c, err := d.DialContext(ctx, network, f.echo)
	if err != nil {
		return nil, err
	}
	fc := &fakeConn{Conn: c, net: f, closed: make(chan struct{})}
	if f.fault == closedAtDial {
		fc.closeOnce.Do(func() { close(fc.closed) })
		_ = c.Close()
	}
	return fc, nil
}

func (f *fakeNet) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.names[host]; ok {
		return []string{a}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f *fakeNet) Listen(string, string) (net.Listener, error) {
	return nil, errors.New("not supported")
}

func (f *fakeNet) ListenPacket(string, string) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

func (f *fakeNet) takeDials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.dials
	f.dials = nil
	return d
}

// fault is a failure of each connection of a fakeNet.
type fault int

const (
	noFault fault = iota
	// writeFails makes each write fail.
	writeFails
	// readFails makes each read fail, and each write waits for the close.
	readFails
	// closedAtDial makes the dial return a closed connection.
	closedAtDial
)

// fakeConn is a connection of a fakeNet. It counts its closes, and after the
// close it has no remote address, as a netstack UDP connection.
type fakeConn struct {
	net.Conn
	net       *fakeNet
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *fakeConn) Read(b []byte) (int, error) {
	if c.net.fault == readFails {
		return 0, os.ErrDeadlineExceeded
	}
	return c.Conn.Read(b)
}

func (c *fakeConn) Write(b []byte) (int, error) {
	switch c.net.fault {
	case writeFails:
		return 0, errors.New("write failed")
	case readFails:
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

func (c *fakeConn) RemoteAddr() net.Addr {
	select {
	case <-c.closed:
		return nil
	default:
		return c.Conn.RemoteAddr()
	}
}

func (c *fakeConn) Close() error {
	c.net.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// startServer starts a proxy with the upstream and fallback networks, and
// returns its address.
func startServer(t *testing.T, upstream, fallback *fakeNet) string {
	t.Helper()
	addr := freePort(t)
	srv := socksproxy.NewServer(addr, upstream, fallback)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(func() {
		_ = srv.Close()
		cancel()
	})
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "socks proxy never started listening")
	return addr
}

// TestUDPAssociate checks that a datagram of a UDP ASSOCIATE goes through the
// network of its destination, and that the network gets the resolved address.
func TestUDPAssociate(t *testing.T) {
	const vpcAddr = "fd61:706f:7879:12::9"
	names := map[string]string{"web.vpc.test": vpcAddr, "local.vpc.test": "127.0.0.1"}
	upstream := newFakeNet(t, "upstream", names)
	fallback := newFakeNet(t, "fallback", nil)
	addr := startServer(t, upstream, fallback)

	cases := []struct {
		name     string
		dst      string
		wantNet  *fakeNet
		wantDial string
	}{
		{name: "VPC address", dst: "[" + vpcAddr + "]:7", wantNet: upstream, wantDial: "udp [" + vpcAddr + "]:7"},
		{name: "VPC name", dst: "web.vpc.test:7", wantNet: upstream, wantDial: "udp [" + vpcAddr + "]:7"},
		{name: "VPC name of a host address", dst: "local.vpc.test:7", wantNet: fallback, wantDial: "udp 127.0.0.1:7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A destination of a UDP ASSOCIATE is not a SOCKS command.
			commands := commandCount()
			u := openAssociate(t, addr)
			send(t, u, tc.dst)
			require.Equal(t, tc.wantNet.name, answer(t, u), "network that answered")
			require.Equal(t, []string{tc.wantDial}, tc.wantNet.takeDials())
			require.Empty(t, upstream.takeDials())
			require.Empty(t, fallback.takeDials())
			require.Equal(t, commands, commandCount())
		})
	}
}

// TestUDPAssociateFaults checks that the proxy closes a failed UDP connection
// one time, and that it continues to serve after the failure.
func TestUDPAssociateFaults(t *testing.T) {
	cases := []struct {
		name  string
		fault fault
	}{
		{name: "write fails", fault: writeFails},
		{name: "read fails while a write waits", fault: readFails},
		{name: "dial returns a closed connection", fault: closedAtDial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newFakeNet(t, "upstream", nil)
			upstream.fault = tc.fault
			addr := startServer(t, upstream, newFakeNet(t, "fallback", nil))

			send(t, openAssociate(t, addr), "[fd61:706f:7879:12::9]:7")
			require.Eventually(t, func() bool { return upstream.closes.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
			require.Never(t, func() bool { return upstream.closes.Load() > 1 }, 500*time.Millisecond, 10*time.Millisecond)
			require.Len(t, upstream.takeDials(), 1)

			u := openAssociate(t, addr)
			send(t, u, "127.0.0.1:7")
			require.Equal(t, "fallback", answer(t, u))
		})
	}
}

// commandCount returns the sum of the SOCKS command counts.
func commandCount() float64 {
	var n float64
	for _, cmd := range []string{"connect", "bind", "udp"} {
		for _, result := range []string{"success", "failure"} {
			n += testutil.ToFloat64(socksproxy.SocksCommands.WithLabelValues(cmd, result))
		}
	}
	return n
}

// openAssociate opens a UDP ASSOCIATE on the proxy at addr, and returns a UDP
// socket that is connected to the relay address of the association.
func openAssociate(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	ctl, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctl.Close() })
	require.NoError(t, ctl.SetDeadline(time.Now().Add(5*time.Second)))
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
	t.Cleanup(func() { _ = u.Close() })
	require.NoError(t, u.SetDeadline(time.Now().Add(2*time.Second)))
	return u
}

// send sends one datagram to dst through the association of u.
func send(t *testing.T, u *net.UDPConn, dst string) {
	t.Helper()
	dg, err := statute.NewDatagram(dst, []byte("ping"))
	require.NoError(t, err)
	_, err = u.Write(dg.Bytes())
	require.NoError(t, err)
}

// answer returns the data of the next datagram on u.
func answer(t *testing.T, u *net.UDPConn) string {
	t.Helper()
	buf := make([]byte, 1500)
	n, err := u.Read(buf)
	require.NoError(t, err, "no answer to the datagram")
	got, err := statute.ParseDatagram(buf[:n])
	require.NoError(t, err)
	return string(got.Data)
}
