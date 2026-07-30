package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsConnectionUnknown separates the two things a 404 can mean: the relay
// forgot this connection (fatal, re-dial) versus the relay does not serve the
// path at all (transient from the caller's view — an older relay).
func TestIsConnectionUnknown(t *testing.T) {
	mk := func(code int, body string) error {
		return &StatusError{Method: http.MethodGet, URL: "https://relay:6081/x", Code: code, Status: "s", Body: body}
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "connection forgotten", err: mk(404, ConnectionNotFoundMessage+"\n"), want: true},
		{name: "wrapped connection forgotten", err: fmt.Errorf("refresh: %w", mk(404, ConnectionNotFoundMessage)), want: true},
		{name: "unregistered path on older relay", err: mk(404, "404 page not found\n"), want: false},
		{name: "empty body 404", err: mk(404, ""), want: false},
		{name: "right body wrong code", err: mk(500, ConnectionNotFoundMessage), want: false},
		{name: "unrelated error", err: errors.New("connection refused"), want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsConnectionUnknown(tc.err))
		})
	}
}

func TestStatusError(t *testing.T) {
	notFound := &StatusError{
		Method: http.MethodGet,
		URL:    "https://relay:6081/v1/tunnel/default/routes?id=abc",
		Code:   http.StatusNotFound,
		Status: "404 Not Found",
		Body:   "Connection not found\n",
	}

	cases := []struct {
		name    string
		err     error
		code    int
		want    bool
		message string
	}{
		{
			name:    "matching code",
			err:     notFound,
			code:    http.StatusNotFound,
			want:    true,
			message: "GET https://relay:6081/v1/tunnel/default/routes?id=abc: unexpected status 404 Not Found: Connection not found\n",
		},
		{
			name: "different code",
			err:  notFound,
			code: http.StatusUnauthorized,
			want: false,
		},
		{
			name: "wrapped",
			err:  fmt.Errorf("refresh routes: %w", notFound),
			code: http.StatusNotFound,
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("connection refused"),
			code: http.StatusNotFound,
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			code: http.StatusNotFound,
			want: false,
		},
		{
			name:    "empty body omits the suffix",
			err:     &StatusError{Method: http.MethodDelete, URL: "https://relay:6081/x", Code: 500, Status: "500 Internal Server Error"},
			code:    http.StatusInternalServerError,
			want:    true,
			message: "DELETE https://relay:6081/x: unexpected status 500 Internal Server Error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsStatus(tc.err, tc.code))
			if tc.message != "" {
				require.Equal(t, tc.message, tc.err.Error())
			}
		})
	}
}

// stubRoundTripper answers every request with a fixed status and body.
type stubRoundTripper struct {
	status int
	body   string
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: s.status,
		Status:     fmt.Sprintf("%d %s", s.status, http.StatusText(s.status)),
		Body:       io.NopCloser(bytes.NewBufferString(s.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestRoutesSurfacesStatusError pins the wiring the agent's route refresh
// depends on: a relay that has forgotten the connection answers 404, and that
// must reach the caller as an inspectable *StatusError rather than an opaque
// formatted string. Without this the agent cannot tell "re-dial now" from a
// transient failure worth retrying.
//
// The "endpoint missing" case is the one that makes this more than a status
// check. The relay's mux answers a bare 404 for any path it does not serve, so
// a newer agent polling an older relay that predates GET .../routes gets 404 on
// every refresh. Treating that as "my connection is gone" would tear down a
// perfectly healthy session every 30s, forever — strictly worse than the stale
// route set the agent would otherwise run with.
func TestRoutesSurfacesStatusError(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		wantFatal bool
	}{
		{name: "connection forgotten", status: http.StatusNotFound, body: ConnectionNotFoundMessage + "\n", wantFatal: true},
		{name: "endpoint missing on older relay", status: http.StatusNotFound, body: "404 page not found\n"},
		{name: "unauthorized", status: http.StatusUnauthorized, body: "Unauthorized\n"},
		{name: "relay hiccup", status: http.StatusInternalServerError, body: "boom"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, err := url.Parse("https://relay.invalid:6081")
			require.NoError(t, err)
			c := &Client{
				http:       &http.Client{Transport: &stubRoundTripper{status: tc.status, body: tc.body}},
				baseURL:    base,
				tunnelName: "default",
				token:      "t",
				agent:      "a",
			}

			resp, err := c.Routes(context.Background(), "conn-1")
			require.Nil(t, resp)
			require.Error(t, err)

			var se *StatusError
			require.ErrorAs(t, err, &se)
			require.Equal(t, tc.status, se.Code)
			require.Contains(t, se.Body, tc.body)
			require.Equal(t, tc.wantFatal, IsConnectionUnknown(err))
		})
	}
}
