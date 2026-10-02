package vpc

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/dpeckett/network"

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
		wantInsecure  bool
	}{
		{
			name:          "defaults without NET_ADMIN",
			host:          "Build-Host.example.com",
			wantName:      "build-host",
			wantMode:      agent.TransportAuto,
			wantDriver:    driverNetstack,
			wantSocksAddr: "localhost:1080",
			wantTunIfname: "apoxy0",
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
			name:         "insecure skip verify",
			args:         []string{"--insecure-skip-verify"},
			host:         "node1",
			wantName:     "node1",
			wantDriver:   driverNetstack,
			wantInsecure: true,
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
			require.Equal(t, tc.wantInsecure, cfg.InsecureSkipVerify)
			if tc.wantSocksAddr != "" || cmd.Flags().Changed("socks-addr") {
				require.Equal(t, tc.wantSocksAddr, o.socksAddr)
			}
			if tc.wantTunIfname != "" {
				require.Equal(t, tc.wantTunIfname, o.tunIfname)
			}
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
			n := &forwardNetwork{Network: local, host: host, routes: tc.routes}
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
