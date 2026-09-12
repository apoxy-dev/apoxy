package bootstrap

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/gateway/utils/proto"
)

func TestGetRenderedBootstrapConfig(t *testing.T) {
	origDetector := defaultDetector
	defer func() { defaultDetector = origDetector }()

	mockReader := &MockFileReader{
		files: map[string][]byte{
			"/sys/fs/cgroup/memory.max": []byte("2147483648\n"),
		},
	}
	mockDetector := NewCgroupMemoryDetector()
	mockDetector.fileReader = mockReader
	defaultDetector = mockDetector
	result := GetCgroupMemoryLimit()
	assert.Equal(t, uint64(2147483648), result)

	cases := []struct {
		name            string
		overrideOptions []BootstrapOption
	}{
		{
			name: "overload-manager",
			overrideOptions: []BootstrapOption{
				WithOverloadMaxHeapSizeBytes(1073741824), // 1GB
				WithOverloadMaxActiveConnections(50000),
			},
		},
		{
			name: "overload-manager-cgroup",
			overrideOptions: []BootstrapOption{
				WithOverloadMaxActiveConnections(50000),
			},
		},
		{
			name: "otel-metrics",
			overrideOptions: []BootstrapOption{
				WithOtelMetricSink("otel-collector.monitoring.svc", 4317),
				WithStatsFlushInterval(15 * time.Second),
				WithOverloadMaxActiveConnections(50000),
			},
		},
		{
			name: "otel-metrics-identity",
			overrideOptions: []BootstrapOption{
				WithOtelMetricSink("otel-collector.monitoring.svc", 4317),
				WithMetricSinkIdentity("my-proxy", "backplane-0", "3a1b2c4d-0000-0000-0000-000000000000"),
				WithOverloadMaxActiveConnections(50000),
			},
		},
		{
			name: "watchdog-custom",
			overrideOptions: []BootstrapOption{
				WithWatchdogTimeouts(500*time.Millisecond, 2*time.Second),
				WithOverloadMaxActiveConnections(50000),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetRenderedBootstrapConfig(tc.overrideOptions...)
			require.NoError(t, err)

			if *overrideTestData {
				// nolint:gosec
				err = os.WriteFile(path.Join("testdata", "render", fmt.Sprintf("%s.yaml", tc.name)), []byte(got), 0644)
				require.NoError(t, err)
				return
			}

			expected, err := readTestData(tc.name)
			require.NoError(t, err)
			assert.Equal(t, expected, got)

			// The golden is compared as a string, so it can drift into YAML
			// that Envoy rejects without any test noticing. Parse it as a
			// bootstrap proto to keep the render honest.
			require.NoError(t, proto.FromYAML([]byte(got), &bootstrapv3.Bootstrap{}))
		})
	}
}

func readTestData(caseName string) (string, error) {
	filename := path.Join("testdata", "render", fmt.Sprintf("%s.yaml", caseName))

	b, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// TestMetricSinkIdentityTags checks the fixed stats tags the identity renders.
// A self-hosted install has no project, which leaves that tag out.
func TestMetricSinkIdentityTags(t *testing.T) {
	cases := []struct {
		name string
		opts []BootstrapOption
		want map[string]string
	}{
		{
			name: "no identity adds no tags",
			opts: []BootstrapOption{WithOtelMetricSink("otel-collector", 4317)},
		},
		{
			name: "identity with a project",
			opts: []BootstrapOption{
				WithOtelMetricSink("otel-collector", 4317),
				WithMetricSinkIdentity("my-proxy", "backplane-0", "project-1"),
			},
			want: map[string]string{
				"apoxy.proxy":      "my-proxy",
				"apoxy.replica":    "backplane-0",
				"apoxy.project_id": "project-1",
			},
		},
		{
			name: "identity without a project leaves the tag out",
			opts: []BootstrapOption{
				WithOtelMetricSink("otel-collector", 4317),
				WithMetricSinkIdentity("my-proxy", "backplane-0", ""),
			},
			want: map[string]string{
				"apoxy.proxy":   "my-proxy",
				"apoxy.replica": "backplane-0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetRenderedBootstrapConfig(tc.opts...)
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
