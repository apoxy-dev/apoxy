// SPDX-License-Identifier: AGPL-3.0-only

package rpc_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/testpb"
)

func TestJSONHandler(t *testing.T) {
	mux := rpc.NewMux()
	testpb.RegisterEchoServer(mux, &echoServer{name: "json"})
	srv := httptest.NewServer(rpc.JSONHandler(mux))
	defer srv.Close()

	const echo = "/apoxy.vpc.rpc.test.v1.Echo/"
	cases := []struct {
		name       string
		httpMethod string
		path       string
		body       string
		wantStatus int
		wantLines  []string // JSON values, compared after decode.
	}{
		{"unary", "POST", echo + "Unary", `{"text":"hi"}`, 200,
			[]string{`{"text":"hi","servedBy":"json"}`}},
		{"bytes field", "POST", echo + "Unary", `{"text":"hi","payload":"AQI="}`, 200,
			[]string{`{"text":"hi","servedBy":"json","payload":"AQI="}`}},
		{"handler error", "POST", echo + "Unary", `{"text":"code 5"}`, 404,
			[]string{`{"error":{"code":"NotFound","message":"handler error"}}`}},
		{"no conn in context", "POST", echo + "Unary", `{"text":"metadata"}`, 500,
			[]string{`{"error":{"code":"Internal","message":"no conn"}}`}},
		{"no request message", "POST", echo + "Unary", ``, 400,
			[]string{`{"error":{"code":"InvalidArgument","message":"missing request message"}}`}},
		{"server stream", "POST", echo + "ServerStream", `{"text":"s","count":2}`, 200,
			[]string{`{"text":"s","servedBy":"json"}`, `{"text":"s","servedBy":"json","seq":1}`}},
		{"client stream", "POST", echo + "ClientStream", `{"text":"a"} {"text":"b"}`, 200,
			[]string{`{"text":"a,b","servedBy":"json"}`}},
		{"bidi", "POST", echo + "Bidi", "{\"text\":\"a\"}\n{\"text\":\"b\"}\n", 200,
			[]string{`{"text":"a","servedBy":"json"}`, `{"text":"b","servedBy":"json","seq":1}`}},
		{"error after a message", "POST", echo + "Bidi", `{"text":"a"} {"text":`, 200,
			[]string{`{"text":"a","servedBy":"json"}`, `{"error":{"code":"InvalidArgument","message":"decode JSON message: unexpected EOF"}}`}},
		{"unknown field", "POST", echo + "Unary", `{"nope":1}`, 400, nil},
		{"unknown method", "POST", echo + "Nope", `{}`, 501,
			[]string{`{"error":{"code":"Unimplemented","message":"unknown method ` + echo + `Nope"}}`}},
		{"not POST", "GET", echo + "Unary", ``, 405, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.httpMethod, srv.URL+tc.path, strings.NewReader(tc.body))
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, resp.StatusCode, "body: %s", body)
			if tc.wantLines == nil {
				return
			}
			lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
			require.Len(t, lines, len(tc.wantLines), "body: %s", body)
			for i, want := range tc.wantLines {
				assert.Equal(t, decodeJSON(t, want), decodeJSON(t, lines[i]))
			}
		})
	}
}

func decodeJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(s), &v), "line: %s", s)
	return v
}
