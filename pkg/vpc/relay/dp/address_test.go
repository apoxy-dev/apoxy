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
	eni := func(public bool, dev1 string) map[string]string {
		m := map[string]string{
			macs:                                              "0a:00:00:00:00:01/\n" + mac + "/\n",
			macs + "0a:00:00:00:00:01/device-number":          "0",
			macs + mac + "/device-number":                     dev1,
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
	imdsCfg := &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS}
	static := func(mac string, addrs ...string) *configv1alpha1.RelayInterface {
		return &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceStatic, MAC: mac, Addresses: addrs, Gateways: []string{"192.0.2.1", "2001:db8::1"}}
	}
	imdsZeroCopy := &configv1alpha1.RelayInterface{Source: configv1alpha1.RelayInterfaceSourceIMDS, ZeroCopy: true}
	staticZeroCopy := static(mac, "192.0.2.10/24")
	staticZeroCopy.ZeroCopy = true
	for _, tc := range []struct {
		name string
		cfg  *configv1alpha1.RelayInterface
		v2   bool
		data map[string]string
		want dp.Interface
		err  string
	}{
		{
			name: "IMDS: the ENI with device number 1",
			cfg:  imdsCfg, v2: true, data: eni(true, "1"),
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("10.0.1.25/24")},
				Public:   []netip.Addr{netip.MustParseAddr("54.1.2.3")},
				Gateways: []netip.Addr{netip.MustParseAddr("10.0.1.1")},
			},
		},
		{
			name: "IMDS: no public IPv4",
			cfg:  imdsCfg, v2: true, data: eni(false, "1"),
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("10.0.1.25/24")},
				Gateways: []netip.Addr{netip.MustParseAddr("10.0.1.1")},
			},
		},
		{
			name: "IMDS: zero-copy on",
			cfg:  imdsZeroCopy, v2: true, data: eni(false, "1"),
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("10.0.1.25/24")},
				Gateways: []netip.Addr{netip.MustParseAddr("10.0.1.1")},
				ZeroCopy: true,
			},
		},
		{name: "IMDS: no ENI with device number 1", cfg: imdsCfg, v2: true, data: eni(true, "2"), err: "device number 1"},
		{name: "IMDS: no session token", cfg: imdsCfg, v2: false, data: eni(true, "1"), err: "IMDS"},
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
			},
		},
		{
			name: "Static: zero-copy on",
			cfg:  staticZeroCopy,
			want: dp.Interface{
				Name: link.Name, MAC: link.HardwareAddr,
				Own:      []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")},
				Public:   []netip.Addr{netip.MustParseAddr("192.0.2.10")},
				Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
				ZeroCopy: true,
			},
		},
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
			got, err := dp.FindInterface(t.Context(), tc.cfg, opts...)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
