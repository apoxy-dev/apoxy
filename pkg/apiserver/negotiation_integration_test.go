package apiserver

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	coordinationv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
)

const (
	domainRecordsPath = "/apis/core.apoxy.dev/v1alpha3/domainrecords"
	leasesPath        = "/apis/coordination.apoxy.dev/v1/namespaces/default/leases"
)

// TestAPIServerIntegrationContentNegotiation checks that clients which prefer
// protobuf get a JSON answer instead of a 406; see
// server/apiserver.WithJSONAndYAML for why. The lease cases mirror the
// Kubernetes namespace controller, which hangs namespace deletion on a 406.
func TestAPIServerIntegrationContentNegotiation(t *testing.T) {
	srv := startTestServer(t, WithResource(&coordinationv1.Lease{}))
	t.Cleanup(srv.cancel)

	cases := []struct {
		name            string
		method          string
		path            string
		accept          string
		wantStatus      int
		wantContentType string
		wantBody        string
	}{
		{
			name:            "protobuf first falls back to json",
			path:            domainRecordsPath,
			accept:          "application/vnd.kubernetes.protobuf,application/json",
			wantContentType: "application/json",
		},
		{
			name:            "namespace controller deletes lease collection",
			method:          http.MethodDelete,
			path:            leasesPath,
			accept:          "application/vnd.kubernetes.protobuf,application/json",
			wantContentType: "application/json",
		},
		{
			name:            "explicit json is unchanged",
			path:            domainRecordsPath,
			accept:          "application/json",
			wantContentType: "application/json",
		},
		{
			name:            "yaml is still served",
			path:            domainRecordsPath,
			accept:          "application/yaml",
			wantContentType: "application/yaml",
		},
		{
			// PartialObjectMetadataList does implement protobuf and the
			// metadata client depends on it. That transform is encoded by the
			// meta.k8s.io codecs, not by the apoxy ones, so it keeps working.
			name:            "partial object metadata keeps protobuf",
			path:            domainRecordsPath,
			accept:          "application/vnd.kubernetes.protobuf;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1,application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1,application/json",
			wantContentType: "application/vnd.kubernetes.protobuf",
		},
		{
			// The accepted trade-off: a client that offers protobuf and
			// nothing else gets a 406 from negotiation. The server never
			// encoded these types to protobuf, so the only change is that the
			// refusal now names the media types it does serve.
			name:       "protobuf only is rejected",
			path:       domainRecordsPath,
			accept:     "application/vnd.kubernetes.protobuf",
			wantStatus: http.StatusNotAcceptable,
			wantBody:   "Available representations: application/json, application/yaml",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			wantStatus := tc.wantStatus
			if wantStatus == 0 {
				wantStatus = http.StatusOK
			}

			req, err := http.NewRequest(method, "https://"+srv.addr+tc.path, nil)
			require.NoError(t, err)
			req.Header.Set("Accept", tc.accept)

			resp, err := srv.http.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, wantStatus, resp.StatusCode, "body: %s", body)
			if tc.wantContentType != "" {
				require.Contains(t, resp.Header.Get("Content-Type"), tc.wantContentType)
			}
			if tc.wantBody != "" {
				require.Contains(t, string(body), tc.wantBody)
			}
		})
	}
}
