package controllers

import (
	"net/netip"
	"testing"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/gateway/utils/proto"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/bootstrap"
)

// TestBootstrapOptionsMetricSinkIdentity checks the fixed stats tags the Envoy
// stats carry. A self-hosted install has no project, which leaves that tag out.
func TestBootstrapOptionsMetricSinkIdentity(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
		want map[string]string
	}{
		{
			name: "no sink adds no tags",
			opts: []Option{WithProjectID("project-1")},
		},
		{
			name: "sink with a project",
			opts: []Option{
				WithProjectID("project-1"),
				WithOtelMetricSink("otel-collector", 4317),
			},
			want: map[string]string{
				"apoxy.proxy":      "my-proxy",
				"apoxy.replica":    "backplane-0",
				"apoxy.project_id": "project-1",
			},
		},
		{
			name: "sink without a project",
			opts: []Option{WithOtelMetricSink("otel-collector", 4317)},
			want: map[string]string{
				"apoxy.proxy":   "my-proxy",
				"apoxy.replica": "backplane-0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewProxyReconciler(nil, "my-proxy", "backplane-0", netip.Addr{}, "apiserver", tc.opts...)

			got, err := bootstrap.GetRenderedBootstrapConfig(r.bootstrapOptions()...)
			require.NoError(t, err)

			var bs bootstrapv3.Bootstrap
			require.NoError(t, proto.FromYAML([]byte(got), &bs))

			tags := map[string]string{}
			for _, tag := range bs.GetStatsConfig().GetStatsTags() {
				tags[tag.GetTagName()] = tag.GetFixedValue()
			}
			if len(tc.want) == 0 {
				assert.Empty(t, tags)
				return
			}
			assert.Equal(t, tc.want, tags)
		})
	}
}
