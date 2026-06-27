package apiserviceproxy

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestResolveAPIProxyHost(t *testing.T) {
	t.Parallel()

	projectID := uuid.MustParse("3340b6b9-585d-4ecd-8703-5f309a46562d")
	testCases := []struct {
		name      string
		projectID uuid.UUID
		apiHost   string
		want      string
	}{
		{name: "default empty", projectID: projectID, apiHost: "", want: projectID.String() + "." + defaultAPIProxyHost},
		{name: "default explicit", projectID: projectID, apiHost: defaultAPIHost, want: projectID.String() + "." + defaultAPIProxyHost},
		{name: "staging api host", projectID: projectID, apiHost: "api-staging.apoxy.dev", want: projectID.String() + ".apiz-staging.apoxy.dev"},
		{name: "prod apiz host passthrough", projectID: projectID, apiHost: "apiz.apoxy.dev", want: projectID.String() + ".apiz.apoxy.dev"},
		{name: "staging apiz host passthrough", projectID: projectID, apiHost: "apiz-staging.apoxy.dev", want: projectID.String() + ".apiz-staging.apoxy.dev"},
		{name: "already project scoped", projectID: projectID, apiHost: projectID.String() + ".apiz-staging.apoxy.dev", want: projectID.String() + ".apiz-staging.apoxy.dev"},
		{name: "custom passthrough", projectID: projectID, apiHost: "custom.example.com", want: "custom.example.com"},
		{name: "no project id", projectID: uuid.Nil, apiHost: "api-staging.apoxy.dev", want: "apiz-staging.apoxy.dev"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, resolveAPIProxyHost(tc.projectID, tc.apiHost))
		})
	}
}

func TestNewCloudReverseProxyRewritesHostHeader(t *testing.T) {
	t.Parallel()

	remote, err := url.Parse("https://apiz-staging.apoxy.dev")
	require.NoError(t, err)

	proxy := newCloudReverseProxy(remote)
	req := httptest.NewRequest("GET", "https://kube-controller/apis/gateway.apoxy.dev/v1", nil)
	proxy.Director(req)

	require.Equal(t, "https", req.URL.Scheme)
	require.Equal(t, "apiz-staging.apoxy.dev", req.URL.Host)
	require.Equal(t, "apiz-staging.apoxy.dev", req.Host)
	require.Equal(t, "/apis/gateway.apoxy.dev/v1", req.URL.Path)
}
