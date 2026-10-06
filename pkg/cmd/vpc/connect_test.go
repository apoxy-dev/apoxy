package vpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/dpeckett/network"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/vpc/agent"
)

func TestAgentConfig(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		host   string
		canTun bool

		wantErr       bool
		wantName      string
		wantMode      agent.TransportMode
		wantDriver    string
		wantMTU       int
		wantRoutes    []netip.Prefix
		wantLabels    map[string]string
		wantSocksAddr string
		wantTunIfname string
		wantSessions  int
		wantAdminAddr string
	}{
		{
			name:          "defaults without NET_ADMIN",
			host:          "Build-Host.example.com",
			wantName:      "build-host",
			wantMode:      agent.TransportAuto,
			wantDriver:    driverNetstack,
			wantSocksAddr: "localhost:1080",
			wantTunIfname: "apoxy0",
			wantSessions:  2,
		},
		{
			name:       "auto driver with NET_ADMIN",
			host:       "node1",
			canTun:     true,
			wantName:   "node1",
			wantDriver: driverTun,
		},
		{
			name:       "netstack driver with NET_ADMIN",
			args:       []string{"--driver", "netstack"},
			host:       "node1",
			canTun:     true,
			wantName:   "node1",
			wantDriver: driverNetstack,
		},
		{
			name:       "tun driver",
			args:       []string{"--driver", "tun", "--tun-ifname", "vpc0"},
			host:       "node1",
			wantErr:    runtime.GOOS != "linux",
			wantName:   "node1",
			wantDriver: driverTun,
		},
		{
			name:    "unknown driver",
			args:    []string{"--driver", "afxdp"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:       "psp transport",
			args:       []string{"--transport", "psp"},
			host:       "node1",
			wantName:   "node1",
			wantMode:   agent.TransportPSP,
			wantDriver: driverNetstack,
		},
		{
			name:       "quic transport",
			args:       []string{"--transport", "quic"},
			host:       "node1",
			wantName:   "node1",
			wantMode:   agent.TransportQUIC,
			wantDriver: driverNetstack,
		},
		{
			name:    "unknown transport",
			args:    []string{"--transport", "tcp"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:       "lowest mtu",
			args:       []string{"--mtu", "1280"},
			host:       "node1",
			wantName:   "node1",
			wantDriver: driverNetstack,
			wantMTU:    1280,
		},
		{
			name:       "highest mtu",
			args:       []string{"--mtu", "1412"},
			host:       "node1",
			wantName:   "node1",
			wantDriver: driverNetstack,
			wantMTU:    1412,
		},
		{
			name:    "mtu too low",
			args:    []string{"--mtu", "1279"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:    "mtu too high",
			args:    []string{"--mtu", "1413"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:       "routes and labels",
			args:       []string{"--route", "10.0.0.0/16", "--route", "fd00:1::/64", "--label", "app=web", "--label", "zone=a"},
			host:       "node1",
			wantName:   "node1",
			wantDriver: driverNetstack,
			wantRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("fd00:1::/64")},
			wantLabels: map[string]string{"app": "web", "zone": "a"},
		},
		{
			name:    "bad route",
			args:    []string{"--route", "10.0.0.0"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:       "explicit name",
			args:       []string{"--name", "web-1"},
			host:       "node1",
			wantName:   "web-1",
			wantDriver: driverNetstack,
		},
		{
			name:    "bad name",
			args:    []string{"--name", "Web_1"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:    "no name and no host name",
			wantErr: true,
		},
		{
			name:         "one relay",
			args:         []string{"--relays", "1"},
			host:         "node1",
			wantName:     "node1",
			wantDriver:   driverNetstack,
			wantSessions: 1,
		},
		{
			name:         "three relays",
			args:         []string{"--relays", "3"},
			host:         "node1",
			wantName:     "node1",
			wantDriver:   driverNetstack,
			wantSessions: 3,
		},
		{
			name:    "no relays",
			args:    []string{"--relays", "0"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:    "too many relays",
			args:    []string{"--relays", "4"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:          "admin socket",
			args:          []string{"--admin-addr", "/run/apoxy/agent.sock"},
			host:          "node1",
			wantName:      "node1",
			wantDriver:    driverNetstack,
			wantAdminAddr: "/run/apoxy/agent.sock",
		},
		{
			name:    "admin TCP address",
			args:    []string{"--admin-addr", "localhost:8080"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:    "admin URL",
			args:    []string{"--admin-addr", "tcp://127.0.0.1:8080"},
			host:    "node1",
			wantErr: true,
		},
		{
			name:          "socks off",
			args:          []string{"--socks-addr", ""},
			host:          "node1",
			wantName:      "node1",
			wantDriver:    driverNetstack,
			wantSocksAddr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var o connectOptions
			cmd := &cobra.Command{}
			o.addFlags(cmd)
			require.NoError(t, cmd.ParseFlags(tc.args))

			cfg, driver, err := o.agentConfig(tc.host, tc.canTun)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantName, cfg.Name)
			require.Equal(t, tc.wantMode, cfg.TransportMode)
			require.Equal(t, tc.wantDriver, driver)
			require.Equal(t, tc.wantMTU, cfg.MTU)
			require.Equal(t, tc.wantRoutes, cfg.Routes)
			require.Equal(t, tc.wantLabels, cfg.Labels)
			if tc.wantSessions != 0 {
				require.Equal(t, tc.wantSessions, cfg.Sessions)
			}
			if tc.wantSocksAddr != "" || cmd.Flags().Changed("socks-addr") {
				require.Equal(t, tc.wantSocksAddr, o.socksAddr)
			}
			if tc.wantTunIfname != "" {
				require.Equal(t, tc.wantTunIfname, o.tunIfname)
			}
			require.Equal(t, tc.wantAdminAddr, o.adminAddr)
		})
	}
}

func TestSocketFamily(t *testing.T) {
	cases := []struct {
		name    string
		relays  []string
		want    string
		wantErr bool
	}{
		{name: "IPv4", relays: []string{"192.0.2.1:443", "192.0.2.2:443"}, want: "udp4"},
		{name: "IPv6", relays: []string{"[2001:db8::1]:443"}, want: "udp6"},
		{name: "both families", relays: []string{"192.0.2.1:443", "[2001:db8::1]:443"}, want: "udp"},
		{name: "one relay does not resolve", relays: []string{"no-port", "[2001:db8::1]:443"}, want: "udp6"},
		{name: "no relay resolves", relays: []string{"no-port"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := socketFamily(tc.relays)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// dialLog is a network that records the addresses that it dials.
type dialLog struct {
	network.Network
	dialed []string
}

func (d *dialLog) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	d.dialed = append(d.dialed, addr)
	return nil, nil
}

func TestForwardNetwork(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}
	cases := []struct {
		name     string
		routes   []netip.Prefix
		addr     string
		wantHost bool
	}{
		{name: "no routes", addr: "10.9.0.5:80"},
		{name: "IPv4 route", routes: routes, addr: "10.9.0.5:80", wantHost: true},
		{name: "IPv4-mapped route", routes: routes, addr: "[::ffff:10.9.0.5]:80", wantHost: true},
		{name: "IPv6 route", routes: routes, addr: "[2001:db8::5]:80", wantHost: true},
		{name: "no route", routes: routes, addr: "10.8.0.5:80"},
		{name: "overlay address", routes: routes, addr: "[fd61:706f:7879:12:3456:7800::1]:80"},
		{name: "overlay address with a default route", routes: []netip.Prefix{netip.MustParsePrefix("::/0")}, addr: "[fd61:706f:7879:12:3456:7800::1]:80"},
		{name: "default route", routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, addr: "192.0.2.1:443", wantHost: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			local, host := &dialLog{}, &dialLog{}
			n := newForwardNetwork(local, host, tc.routes)
			_, err := n.DialContext(context.Background(), "tcp", tc.addr)
			require.NoError(t, err)
			if tc.wantHost {
				require.Equal(t, []string{tc.addr}, host.dialed)
				require.Empty(t, local.dialed)
			} else {
				require.Equal(t, []string{tc.addr}, local.dialed)
				require.Empty(t, host.dialed)
			}
		})
	}
}

// fakeOverlay keeps the overlay addresses and the own routes of a driver.
type fakeOverlay struct {
	addrs  []netip.Addr
	routes []netip.Prefix
}

func (f *fakeOverlay) setAddr(old, addr netip.Addr) error {
	if old.IsValid() {
		if err := f.delAddr(old); err != nil {
			return err
		}
	}
	f.addrs = append(f.addrs, addr)
	return nil
}

func (f *fakeOverlay) delAddr(addr netip.Addr) error {
	i := slices.Index(f.addrs, addr)
	if i < 0 {
		return errors.New("no such address")
	}
	f.addrs = slices.Delete(f.addrs, i, i+1)
	return nil
}

func (f *fakeOverlay) route(_, _ []netip.Prefix) {}

func (f *fakeOverlay) own(routes []netip.Prefix) { f.routes = routes }

func TestHostDeviceAttachments(t *testing.T) {
	addr := netip.MustParseAddr
	pfx := netip.MustParsePrefix
	base := addr("fd00::1")
	steps := []struct {
		name      string
		attach    *agent.Attachment
		detach    string
		wantAddrs []netip.Addr
		wantHost  []string // Addresses in the own routes. They forward to the host network.
	}{
		{
			name:      "attach x",
			attach:    &agent.Attachment{Name: "x", Address: addr("fd00:1::1"), Routes: []netip.Prefix{pfx("10.1.0.0/16")}},
			wantAddrs: []netip.Addr{base, addr("fd00:1::1")},
			wantHost:  []string{"10.0.0.1", "10.1.0.1"},
		},
		{
			name:      "x moves",
			attach:    &agent.Attachment{Name: "x", Address: addr("fd00:2::1"), Routes: []netip.Prefix{pfx("10.1.0.0/16")}},
			wantAddrs: []netip.Addr{base, addr("fd00:2::1")},
			wantHost:  []string{"10.0.0.1", "10.1.0.1"},
		},
		{
			name:      "attach y",
			attach:    &agent.Attachment{Name: "y", Address: addr("fd00:3::1")},
			wantAddrs: []netip.Addr{base, addr("fd00:2::1"), addr("fd00:3::1")},
			wantHost:  []string{"10.0.0.1", "10.1.0.1"},
		},
		{
			name:      "detach x",
			detach:    "x",
			wantAddrs: []netip.Addr{base, addr("fd00:3::1")},
			wantHost:  []string{"10.0.0.1"},
		},
		{
			name:      "detach x again",
			detach:    "x",
			wantAddrs: []netip.Addr{base, addr("fd00:3::1")},
			wantHost:  []string{"10.0.0.1"},
		},
	}
	routes := []netip.Prefix{pfx("10.0.0.0/16")}
	dev := &fakeOverlay{addrs: []netip.Addr{base}, routes: routes}
	h := &hostDevice{dev: dev, addr: base, routes: routes, fwd: newForwardNetwork(nil, nil, routes)}
	for _, st := range steps {
		if st.attach != nil {
			h.attachment(*st.attach)
		} else {
			h.detach(agent.Attachment{Name: st.detach})
		}
		require.Equal(t, st.wantAddrs, dev.addrs, st.name)
		for _, a := range []string{"10.0.0.1", "10.1.0.1"} {
			want := slices.Contains(st.wantHost, a)
			require.Equal(t, want, h.fwd.routed(addr(a)), "%s: %s", st.name, a)
			own := slices.ContainsFunc(dev.routes, func(p netip.Prefix) bool { return p.Contains(addr(a)) })
			require.Equal(t, want, own, "%s: own route of %s", st.name, a)
		}
	}
}

func TestConnectError(t *testing.T) {
	other := errors.New("relay session closed")
	cases := []struct {
		name     string
		err      error
		wantText string // Empty means that the error does not change.
	}{
		{name: "other error", err: other},
		{
			name:     "relays need a newer agent",
			err:      fmt.Errorf("%w: relay 192.0.2.1:443: agent revision 1 is below the relay minimum 2", agent.ErrUpgrade),
			wantText: `this version of the Apoxy CLI (` + build.BuildVersion + `) is too old for the VPC: agent needs an upgrade: relay 192.0.2.1:443: agent revision 1 is below the relay minimum 2; run "apoxy upgrade" and connect again`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := connectError(tc.err)
			require.ErrorIs(t, err, tc.err)
			if tc.wantText == "" {
				require.Equal(t, tc.err, err)
				return
			}
			require.ErrorIs(t, err, agent.ErrUpgrade)
			require.EqualError(t, err, tc.wantText)
		})
	}
}
