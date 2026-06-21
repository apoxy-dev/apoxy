// SPDX-License-Identifier: AGPL-3.0-only

package workerd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlePublish(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		body       string
		wantStatus int
		wantSocket string // expected registry socket after the call ("" = unchanged/empty)
	}{
		{
			name:       "valid POST updates the registry",
			method:     http.MethodPost,
			body:       `{"residentSocket":"/run/workerd/resident.sock","demux":{"proj:echo":"echo-r1"}}`,
			wantStatus: http.StatusNoContent,
			wantSocket: "/run/workerd/resident.sock",
		},
		{
			name:       "PUT is accepted",
			method:     http.MethodPut,
			body:       `{"residentSocket":"/s.sock","demux":{}}`,
			wantStatus: http.StatusNoContent,
			wantSocket: "/s.sock",
		},
		{
			name:       "missing residentSocket is rejected",
			method:     http.MethodPost,
			body:       `{"demux":{"proj:echo":"echo-r1"}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed JSON is rejected",
			method:     http.MethodPost,
			body:       `{not json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "GET is not allowed",
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewRegistry()
			srv := NewServer(reg)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, publishPath, strings.NewReader(tc.body))
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := reg.ResidentSocket(); got != tc.wantSocket {
				t.Fatalf("registry socket = %q, want %q", got, tc.wantSocket)
			}
		})
	}
}

func TestHandlePublishRoundTripsDemux(t *testing.T) {
	reg := NewRegistry()
	srv := NewServer(reg)
	body := `{"residentSocket":"/s.sock","demux":{"proj:echo":"echo-r1"}}`
	req := httptest.NewRequest(http.MethodPost, publishPath, bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if got, ok := reg.DemuxHeader("echo"); !ok || got != "proj:echo" {
		t.Fatalf("DemuxHeader(echo) = %q,%v", got, ok)
	}
}

func TestValidateLoopbackAddr(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "ipv4 loopback", addr: "127.0.0.1:2021"},
		{name: "ipv6 loopback", addr: "[::1]:2021"},
		{name: "localhost", addr: "localhost:2021"},
		{name: "all interfaces bare port", addr: ":2021", wantErr: true},
		{name: "0.0.0.0 rejected", addr: "0.0.0.0:2021", wantErr: true},
		{name: "non-loopback ip rejected", addr: "10.0.0.5:2021", wantErr: true},
		{name: "no port", addr: "127.0.0.1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLoopbackAddr(tc.addr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateLoopbackAddr(%q) err = %v, wantErr %v", tc.addr, err, tc.wantErr)
			}
		})
	}
}
