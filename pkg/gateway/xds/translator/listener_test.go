// SPDX-License-Identifier: AGPL-3.0-only

package translator

import (
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/pkg/gateway/gatewayapi"
	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
)

// hcmOf pulls the HTTP connection manager out of the listener's default filter
// chain, which is where a plaintext listener's chain lands.
func hcmOf(t *testing.T, l *listenerv3.Listener) *hcmv3.HttpConnectionManager {
	t.Helper()
	chain := l.GetDefaultFilterChain()
	if chain == nil {
		t.Fatal("listener has no default filter chain")
	}
	for _, f := range chain.GetFilters() {
		if f.GetName() != wellknown.HTTPConnectionManager {
			continue
		}
		mgr := new(hcmv3.HttpConnectionManager)
		if err := f.GetTypedConfig().UnmarshalTo(mgr); err != nil {
			t.Fatalf("unmarshal hcm: %v", err)
		}
		return mgr
	}
	t.Fatal("listener has no http connection manager")
	return nil
}

// TestHCMStatPrefix pins the HCM stat prefix to the Gateway listener that
// produced it, so an Envoy stat names one Gateway instead of only a scheme.
// The prefix is gw/<namespace>/<gateway>/<listener>, which is the IR listener
// name gatewayapi.ListenerName builds.
func TestHCMStatPrefix(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		gateway   string
		listener  string
		want      string
	}{
		{
			name:      "plaintext listener",
			namespace: "default",
			gateway:   "eg",
			listener:  "http",
			want:      "gw/default/eg/http",
		},
		{
			name:      "another gateway in the same namespace gets its own prefix",
			namespace: "default",
			gateway:   "second",
			listener:  "http",
			want:      "gw/default/second/http",
		},
		{
			name:      "a second listener on one gateway gets its own prefix",
			namespace: "prod",
			gateway:   "edge",
			listener:  "http-alt",
			want:      "gw/prod/edge/http-alt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the IR name the same way the Gateway API translator does,
			// so the test tracks a rename of that helper rather than pinning a
			// literal that could drift away from it.
			irName := gatewayapi.ListenerName(tc.namespace, tc.gateway, gwapiv1.SectionName(tc.listener))
			xdsListener := &listenerv3.Listener{Name: irName}
			irListener := &ir.HTTPListener{CoreListenerDetails: ir.CoreListenerDetails{Name: irName}}

			if err := (&Translator{}).addXdsHTTPFilterChain(xdsListener, irListener, nil, nil, false); err != nil {
				t.Fatalf("addXdsHTTPFilterChain: %v", err)
			}

			mgr := hcmOf(t, xdsListener)
			if got := mgr.GetStatPrefix(); got != tc.want {
				t.Errorf("stat prefix = %q, want %q", got, tc.want)
			}
			// The route config still keys off the bare IR name; only the stat
			// prefix carries the gw/ marker.
			if got := mgr.GetRds().GetRouteConfigName(); got != irName {
				t.Errorf("route config name = %q, want %q", got, irName)
			}
		})
	}
}
