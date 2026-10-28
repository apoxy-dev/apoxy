// SPDX-License-Identifier: AGPL-3.0-only

package dp_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
)

// someLink returns a link of this host that has a MAC.
func someLink(t *testing.T) net.Interface {
	t.Helper()
	links, err := net.Interfaces()
	require.NoError(t, err)
	for _, l := range links {
		if len(l.HardwareAddr) == 6 && l.HardwareAddr.String() != "00:00:00:00:00:00" {
			return l
		}
	}
	t.Skip("no link with a MAC")
	return net.Interface{}
}

// imdsServer is an IMDS of an instance with two ENIs. Without v2 it refuses session tokens.
func imdsServer(t *testing.T, v2 bool, data map[string]string) string {
	t.Helper()
	const token = "session-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/api/token" {
			if !v2 || r.Method != http.MethodPut || r.Header.Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds") == "" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			_, _ = w.Write([]byte(token))
			return
		}
		if r.Header.Get("X-Aws-Ec2-Metadata-Token") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		v, ok := data[strings.TrimPrefix(r.URL.Path, "/latest/meta-data/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(v))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFindInterface(t *testing.T) {
	link := someLink(t)
	mac := link.HardwareAddr.String()
	const macs = "network/interfaces/macs/"
	// eni gives the link of the test the device number dev, and the other ENI the device number other.
	eni := func(public bool, dev, other string) map[string]string {
		m := map[string]string{
			macs:                                              "0a:00:00:00:00:01/\n" + mac + "/\n",
			macs + "0a:00:00:00:00:01/device-number":          other,
			macs + mac + "/device-number":                     dev,
			macs + mac + "/local-ipv4s":                       "10.0.1.25\n10.0.1.26",
			macs + mac + "/subnet-ipv4-cidr-block":            "10.0.1.0/24",
			macs + "0a:00:00:00:00:01/local-ipv4s":            "10.0.0.5",
			macs + "0a:00:00:00:00:01/subnet-ipv4-cidr-block": "10.0.0.0/24",
		}
		if public {
			m[macs+mac+"/public-ipv4s"] = "54.1.2.3"
		}
		return m
	}
	const (
		shared    = configv1alpha1.RelayInterfaceModeShared
		dedicated = configv1alpha1.RelayInterfaceModeDedicated
	)
	imdsCfg := &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS}
	imdsShared := &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS, Mode: shared}
	imdsDedicated := &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS, Mode: dedicated}
	static := func(mac string, addrs ...string) *configv1alpha1.RelayInterface {
		return &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceStatic, MAC: mac, Addresses: addrs, Gateways: []string{"192.0.2.1", "2001:db8::1"}}
	}
	imdsZeroCopy := &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS, ZeroCopy: true, Mode: dedicated}
	staticZeroCopy := static(mac, "192.0.2.10/24")
	staticZeroCopy.ZeroCopy = true
	staticDedicated := static(mac, "192.0.2.10/24")
	staticDedicated.Mode = dedicated
	staticBadMode := static(mac, "192.0.2.10/24")
	staticBadMode.Mode = "shared"
	primaryENI := dp.Interface{
		Name: link.Name, MAC: link.HardwareAddr,
		Own:      []netip.Prefix{netip.MustParsePrefix("10.0.1.25/24")},
		Public:   []netip.Addr{netip.MustParseAddr("54.1.2.3")},
		Gateways: []netip.Addr{netip.MustParseAddr("10.0.1.1")},
		Mode:     shared,
	}
	for _, tc := range []struct {
		name  string
		cfg   *configv1alpha1.RelayInterface
		cpus  string // relay.cpus of the config.
		v2    bool
		data  map[string]string
		want  dp.Interface
		err   string
		errIs error
	}{
		{name: "IMDS, no mode: Shared, the primary ENI", cfg: imdsCfg, v2: true, data: eni(true, "0", "1"), want: primaryENI},
		{name: "IMDS, Shared: the primary ENI", cfg: imdsShared, v2: true, data: eni(true, "0", "1"), want: primaryENI},
		{name: "IMDS, Shared: no ENI with device number 0", cfg: imdsShared, v2: true, data: eni(true, "2", "1"), err: "device number 0"},
		{
			name: "IMDS, Dedicated: the ENI with device number 1",
			cfg:  imdsDedicated, v2: true, data: eni(true, "1", "0"),
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("10.0.1.25/24")},
				Public:   []netip.Addr{netip.MustParseAddr("54.1.2.3")},
				Gateways: []netip.Addr{netip.MustParseAddr("10.0.1.1")},
				Mode:     dedicated,
			},
		},
		{
			name: "IMDS, Dedicated: no public IPv4",
			cfg:  imdsDedicated, v2: true, data: eni(false, "1", "0"),
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("10.0.1.25/24")},
				Gateways: []netip.Addr{netip.MustParseAddr("10.0.1.1")},
				Mode:     dedicated,
			},
		},
		{
			name: "IMDS, Dedicated: zero-copy on",
			cfg:  imdsZeroCopy, v2: true, data: eni(false, "1", "0"),
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("10.0.1.25/24")},
				Gateways: []netip.Addr{netip.MustParseAddr("10.0.1.1")},
				ZeroCopy: true,
				Mode:     dedicated,
			},
		},
		{name: "IMDS, Dedicated: no ENI with device number 1", cfg: imdsDedicated, v2: true, data: eni(true, "2", "0"), err: "device number 1"},
		// The ENI with device number 1 is the other ENI, which has no link on this host.
		{name: "IMDS, Dedicated: not the primary ENI", cfg: imdsDedicated, v2: true, data: eni(true, "0", "1"), err: "no link has MAC 0a:00:00:00:00:01"},
		{name: "IMDS: no session token", cfg: imdsDedicated, v2: false, data: eni(true, "1", "0"), err: "IMDS"},
		{
			name: "IMDS: mac is only for Static",
			cfg:  &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS, MAC: mac},
			err:  "only for source Static",
		},
		{
			name: "Static: both addresses are the addresses",
			cfg:  static(mac, "192.0.2.10/24", "2001:db8::10/64"),
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24"), netip.MustParsePrefix("2001:db8::10/64")},
				Public:   []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
				Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
				Mode:     shared,
			},
		},
		{
			name: "Static, Dedicated",
			cfg:  staticDedicated,
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")},
				Public:   []netip.Addr{netip.MustParseAddr("192.0.2.10")},
				Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
				Mode:     dedicated,
			},
		},
		{name: "a mode that is not Shared or Dedicated", cfg: staticBadMode, err: `relay interface mode "shared" is not Shared or Dedicated`},
		{
			name: "Static: zero-copy on",
			cfg:  staticZeroCopy,
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")},
				Public:   []netip.Addr{netip.MustParseAddr("192.0.2.10")},
				Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
				ZeroCopy: true,
				Mode:     shared,
			},
		},
		{
			name: "the relay CPUs of the config",
			cfg:  static(mac, "192.0.2.10/24"), cpus: "2-3",
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")},
				Public:   []netip.Addr{netip.MustParseAddr("192.0.2.10")},
				Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
				CPUs:     []int{2, 3},
				Mode:     shared,
			},
		},
		{name: "a bad CPU list", cfg: static(mac, "192.0.2.10/24"), cpus: "3-2", errIs: dp.ErrCPUList},
		{name: "a CPU list that is not numbers", cfg: imdsCfg, cpus: "two", errIs: dp.ErrCPUList},
		{name: "Static: an address that is not a prefix", cfg: static(mac, "192.0.2.10"), err: "address"},
		{name: "Static: no addresses", cfg: static(mac), err: "no addresses"},
		{name: "Static: no link with the MAC", cfg: static("0a:00:00:00:00:99", "192.0.2.10/24"), err: "no link has MAC"},
		{name: "no source", cfg: &configv1alpha1.RelayInterface{}, err: "is not IMDS or Static"},
		{name: "no config", err: "no relay interface"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []func(*imds.Options)
			if tc.data != nil {
				url := imdsServer(t, tc.v2, tc.data)
				opts = append(opts, func(o *imds.Options) { o.Endpoint = url })
			}
			got, err := dp.FindInterface(t.Context(), &configv1alpha1.RelayConfig{Interface: tc.cfg, CPUs: tc.cpus}, opts...)
			if tc.errIs != nil {
				require.ErrorIs(t, err, tc.errIs)
				return
			}
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
