package v1alpha1

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

func TestVPCNetworkValidate(t *testing.T) {
	// The numbers are those of the API: a client can set 1280 to 1412.
	cases := []struct {
		name    string
		mtu     int32
		wantErr bool
	}{
		{name: "unset", mtu: 0},
		{name: "default", mtu: DefaultMTU},
		{name: "max", mtu: MaxMTU},
		{name: "lowest number", mtu: 1280},
		{name: "one below the lowest number", mtu: 1279, wantErr: true},
		{name: "largest number", mtu: 1412},
		{name: "one above the largest number", mtu: 1413, wantErr: true},
		{name: "below the IPv6 minimum", mtu: DefaultMTU - 1, wantErr: true},
		{name: "above the max", mtu: MaxMTU + 1, wantErr: true},
		{name: "negative", mtu: -1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: VPCNetworkSpec{MTU: tc.mtu}}
			errs := n.Validate(context.Background())
			if got := len(errs) > 0; got != tc.wantErr {
				t.Errorf("Validate() = %v, want error %v", errs, tc.wantErr)
			}
			if tc.wantErr && len(errs) == 1 {
				if got, want := errs[0].Field+": "+errs[0].Detail, "spec.mtu: must be from 1280 to 1412"; got != want {
					t.Errorf("Validate() error = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestVPCNetworkValidateUpdate(t *testing.T) {
	bad := &VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: VPCNetworkSpec{MTU: 9000}}
	cases := []struct {
		name    string
		old     *VPCNetwork
		new     *VPCNetwork
		wantErr bool
	}{
		{name: "spec unchanged", old: bad, new: bad.DeepCopy()},
		{name: "deleted", old: bad, new: func() *VPCNetwork {
			n := bad.DeepCopy()
			n.DeletionTimestamp = &metav1.Time{}
			n.Spec.MTU = 9001
			return n
		}()},
		{name: "spec changed to a bad MTU", old: &VPCNetwork{}, new: bad.DeepCopy(), wantErr: true},
		{name: "spec changed to the largest MTU", old: bad, new: &VPCNetwork{Spec: VPCNetworkSpec{MTU: 1412}}},
		{name: "spec changed to one above the largest MTU", old: &VPCNetwork{}, new: &VPCNetwork{Spec: VPCNetworkSpec{MTU: 1413}}, wantErr: true},
		{name: "spec changed to a bad route", old: &VPCNetwork{}, wantErr: true,
			new: &VPCNetwork{Spec: VPCNetworkSpec{Agents: []VPCNetworkAgent{{Name: "site-a", Routes: []VPCNetworkRoute{{Prefix: "0.0.0.0/0"}}}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := tc.new.ValidateUpdate(context.Background(), tc.old)
			if got := len(errs) > 0; got != tc.wantErr {
				t.Errorf("ValidateUpdate() = %v, want error %v", errs, tc.wantErr)
			}
		})
	}
}

func TestVPCNetworkValidateAgents(t *testing.T) {
	route := func(prefix string) VPCNetworkRoute { return VPCNetworkRoute{Prefix: prefix} }
	agent := func(name string, routes ...VPCNetworkRoute) VPCNetworkAgent {
		return VPCNetworkAgent{Name: name, Routes: routes}
	}
	manyRoutes := func(n int) []VPCNetworkRoute {
		out := make([]VPCNetworkRoute, n)
		for i := range out {
			out[i] = route(fmt.Sprintf("10.%d.0.0/16", i))
		}
		return out
	}
	// wantErr is "<field>: <part of the detail>" of the one error. Empty means valid.
	cases := []struct {
		name    string
		agents  []VPCNetworkAgent
		wantErr string
	}{
		{name: "no agents"},
		{name: "agent with no routes", agents: []VPCNetworkAgent{agent("site-a")}},
		{name: "IPv4 and IPv6 routes", agents: []VPCNetworkAgent{agent("site-a", route("10.0.1.0/24"), route("2001:db8:1::/48"))}},
		{name: "host route", agents: []VPCNetworkAgent{agent("site-a", route("192.0.2.7/32"))}},
		{name: "two agents with one prefix", agents: []VPCNetworkAgent{
			agent("site-a-1", VPCNetworkRoute{Prefix: "10.0.1.0/24", Priority: ptr.To[int32](200)}),
			agent("site-a-2", route("10.0.1.0/24")),
		}},
		{name: "one agent with a prefix and a part of it", agents: []VPCNetworkAgent{agent("site-a", route("10.0.0.0/16"), route("10.0.1.0/24"))}},
		{name: "lowest priority", agents: []VPCNetworkAgent{agent("site-a", VPCNetworkRoute{Prefix: "10.0.1.0/24", Priority: ptr.To[int32](0)})}},
		{name: "largest priority", agents: []VPCNetworkAgent{agent("site-a", VPCNetworkRoute{Prefix: "10.0.1.0/24", Priority: ptr.To[int32](255)})}},
		{name: "64 routes", agents: []VPCNetworkAgent{agent("site-a", manyRoutes(64)...)}},
		{name: "IPv6 range next to the overlay range", agents: []VPCNetworkAgent{agent("site-a", route("fd61:706f:787a::/48"))}},

		{name: "65 routes", agents: []VPCNetworkAgent{agent("site-a", manyRoutes(65)...)},
			wantErr: "spec.agents[0].routes: must have at most 64 items"},
		{name: "empty agent name", agents: []VPCNetworkAgent{agent("")},
			wantErr: "spec.agents[0].name: a lowercase RFC 1123 label"},
		{name: "agent name that is not a DNS label", agents: []VPCNetworkAgent{agent("Site_A")},
			wantErr: "spec.agents[0].name: a lowercase RFC 1123 label"},
		{name: "agent two times", agents: []VPCNetworkAgent{agent("site-a"), agent("site-a")},
			wantErr: "spec.agents[1].name: "},
		{name: "prefix two times for one agent", agents: []VPCNetworkAgent{agent("site-a", route("10.0.1.0/24"), route("10.0.1.0/24"))},
			wantErr: "spec.agents[0].routes[1].prefix: "},
		{name: "IPv6 prefix two times in different text", agents: []VPCNetworkAgent{agent("site-a", route("2001:db8::/32"), route("2001:db8:0::/32"))},
			wantErr: "spec.agents[0].routes[1].prefix: "},
		{name: "not a prefix", agents: []VPCNetworkAgent{agent("site-a", route("10.0.1.0"))},
			wantErr: "spec.agents[0].routes[0].prefix: must be an IPv4 or IPv6 prefix"},
		{name: "empty prefix", agents: []VPCNetworkAgent{agent("site-a", route(""))},
			wantErr: "spec.agents[0].routes[0].prefix: must be an IPv4 or IPv6 prefix"},
		{name: "host bits", agents: []VPCNetworkAgent{agent("site-a", route("10.0.1.7/24"))},
			wantErr: "spec.agents[0].routes[0].prefix: must have no host bits: use 10.0.1.0/24"},
		{name: "IPv4-mapped IPv6 prefix", agents: []VPCNetworkAgent{agent("site-a", route("::ffff:10.0.1.0/120"))},
			wantErr: "spec.agents[0].routes[0].prefix: must not be an IPv4-mapped IPv6 prefix"},
		{name: "IPv4 default route", agents: []VPCNetworkAgent{agent("site-a", route("0.0.0.0/0"))},
			wantErr: "spec.agents[0].routes[0].prefix: must not be a default route"},
		{name: "IPv6 default route", agents: []VPCNetworkAgent{agent("site-a", route("::/0"))},
			wantErr: "spec.agents[0].routes[0].prefix: must not be a default route"},
		{name: "overlay range", agents: []VPCNetworkAgent{agent("site-a", route("fd61:706f:7879::/48"))},
			wantErr: "spec.agents[0].routes[0].prefix: must not overlap fd61:706f:7879::/48"},
		{name: "part of the overlay range", agents: []VPCNetworkAgent{agent("site-a", route("fd61:706f:7879:12:3400::/72"))},
			wantErr: "spec.agents[0].routes[0].prefix: must not overlap fd61:706f:7879::/48"},
		{name: "range that contains the overlay range", agents: []VPCNetworkAgent{agent("site-a", route("fd00::/8"))},
			wantErr: "spec.agents[0].routes[0].prefix: must not overlap fd61:706f:7879::/48"},
		{name: "priority below the range", agents: []VPCNetworkAgent{agent("site-a", VPCNetworkRoute{Prefix: "10.0.1.0/24", Priority: ptr.To[int32](-1)})},
			wantErr: "spec.agents[0].routes[0].priority: must be from 0 to 255"},
		{name: "priority above the range", agents: []VPCNetworkAgent{agent("site-a", VPCNetworkRoute{Prefix: "10.0.1.0/24", Priority: ptr.To[int32](256)})},
			wantErr: "spec.agents[0].routes[0].priority: must be from 0 to 255"},
		{name: "error in the second agent", agents: []VPCNetworkAgent{agent("site-a", route("10.0.1.0/24")), agent("site-b", route("10.0.2.0/24"), route("0.0.0.0/0"))},
			wantErr: "spec.agents[1].routes[1].prefix: must not be a default route"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: VPCNetworkSpec{Agents: tc.agents}}
			errs := n.Validate(context.Background())
			if tc.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("Validate() = %v, want no error", errs)
				}
				return
			}
			if len(errs) != 1 {
				t.Fatalf("Validate() = %v, want one error", errs)
			}
			if got := errs[0].Field + ": " + errs[0].Detail; !strings.HasPrefix(got, tc.wantErr) {
				t.Errorf("Validate() error = %q, want the prefix %q", got, tc.wantErr)
			}
		})
	}
}

func TestVPCNetworkValidateRouteHealthCheck(t *testing.T) {
	const hc = "spec.agents[0].routes[0].healthCheck."
	// wantErr is "<field>: <part of the detail>" of the one error. Empty means valid.
	cases := []struct {
		name    string
		prefix  string
		check   VPCNetworkRouteHealthCheck
		wantErr string
	}{
		{name: "only a target: ICMP echo with the defaults", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1"}},
		{name: "all fields", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{
			Target: "10.0.1.1", TCPPort: 443, IntervalSeconds: 5, FailureThreshold: 4, SuccessThreshold: 1}},
		{name: "IPv6 target", prefix: "2001:db8:1::/48", check: VPCNetworkRouteHealthCheck{Target: "2001:db8:1::53", TCPPort: 53}},
		{name: "first address of the prefix", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.0"}},
		{name: "last address of the prefix", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.255"}},
		{name: "target of a host route", prefix: "192.0.2.7/32", check: VPCNetworkRouteHealthCheck{Target: "192.0.2.7"}},
		{name: "lowest numbers", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{
			Target: "10.0.1.1", TCPPort: 1, IntervalSeconds: 1, FailureThreshold: 1, SuccessThreshold: 1}},
		{name: "largest numbers", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{
			Target: "10.0.1.1", TCPPort: 65535, IntervalSeconds: 60, FailureThreshold: 10, SuccessThreshold: 10}},

		{name: "no target", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{TCPPort: 443},
			wantErr: hc + "target: must be an IP address"},
		{name: "target is a host name", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "db.internal"},
			wantErr: hc + "target: must be an IP address"},
		{name: "target is a prefix", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1/32"},
			wantErr: hc + "target: must be an IP address"},
		{name: "target with a port", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1:443"},
			wantErr: hc + "target: must be an IP address"},
		{name: "target one address after the prefix", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.2.0"},
			wantErr: hc + "target: must be an address in the prefix 10.0.1.0/24 of the route"},
		{name: "target one address before the prefix", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.0.255"},
			wantErr: hc + "target: must be an address in the prefix 10.0.1.0/24 of the route"},
		{name: "IPv6 target for an IPv4 prefix", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "2001:db8:1::53"},
			wantErr: hc + "target: must be an address in the prefix 10.0.1.0/24 of the route"},
		{name: "IPv4-mapped IPv6 target for an IPv4 prefix", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "::ffff:10.0.1.1"},
			wantErr: hc + "target: must be an address in the prefix 10.0.1.0/24 of the route"},
		{name: "IPv4 target for an IPv6 prefix", prefix: "2001:db8:1::/48", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1"},
			wantErr: hc + "target: must be an address in the prefix 2001:db8:1::/48 of the route"},
		{name: "IPv6 target with a zone", prefix: "2001:db8:1::/48", check: VPCNetworkRouteHealthCheck{Target: "2001:db8:1::53%eth0"},
			wantErr: hc + "target: must be an address in the prefix 2001:db8:1::/48 of the route"},
		{name: "negative port", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", TCPPort: -1},
			wantErr: hc + "tcpPort: must be from 1 to 65535"},
		{name: "port above the range", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", TCPPort: 65536},
			wantErr: hc + "tcpPort: must be from 1 to 65535"},
		{name: "negative interval", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", IntervalSeconds: -1},
			wantErr: hc + "intervalSeconds: must be from 1 to 60"},
		{name: "interval above the range", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", IntervalSeconds: 61},
			wantErr: hc + "intervalSeconds: must be from 1 to 60"},
		{name: "negative failure threshold", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", FailureThreshold: -1},
			wantErr: hc + "failureThreshold: must be from 1 to 10"},
		{name: "failure threshold above the range", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", FailureThreshold: 11},
			wantErr: hc + "failureThreshold: must be from 1 to 10"},
		{name: "negative success threshold", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", SuccessThreshold: -1},
			wantErr: hc + "successThreshold: must be from 1 to 10"},
		{name: "success threshold above the range", prefix: "10.0.1.0/24", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1", SuccessThreshold: 11},
			wantErr: hc + "successThreshold: must be from 1 to 10"},
		{name: "bad prefix with a good target has only the prefix error", prefix: "0.0.0.0/0", check: VPCNetworkRouteHealthCheck{Target: "10.0.1.1"},
			wantErr: "spec.agents[0].routes[0].prefix: must not be a default route"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := &VPCNetwork{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: VPCNetworkSpec{Agents: []VPCNetworkAgent{
				{Name: "site-a", Routes: []VPCNetworkRoute{{Prefix: tc.prefix, HealthCheck: &tc.check}}},
			}}}
			errs := n.Validate(context.Background())
			if tc.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("Validate() = %v, want no error", errs)
				}
				return
			}
			if len(errs) != 1 {
				t.Fatalf("Validate() = %v, want one error", errs)
			}
			if got := errs[0].Field + ": " + errs[0].Detail; !strings.HasPrefix(got, tc.wantErr) {
				t.Errorf("Validate() error = %q, want the prefix %q", got, tc.wantErr)
			}
		})
	}
}

// The API constant must be the range that the address code uses.
func TestOverlayAddressSpace(t *testing.T) {
	if got, want := OverlayAddressSpace, tunnet.ULAPrefix().String(); got != want {
		t.Errorf("OverlayAddressSpace = %q, want %q", got, want)
	}
}
