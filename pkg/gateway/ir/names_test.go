package ir

import "testing"

func TestParseRouteName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want RouteSource
		ok   bool
	}{
		{name: "http route", in: "httproute/ns/api/rule/0/match/0", want: RouteSource{Kind: "HTTPRoute", Namespace: "ns", Name: "api", Rule: 0}, ok: true},
		{name: "grpc route without matches", in: "grpcroute/ns/echo/rule/2/match/-1", want: RouteSource{Kind: "GRPCRoute", Namespace: "ns", Name: "echo", Rule: 2}, ok: true},
		{name: "no namespace", in: "httproute//api/rule/0/match/0", want: RouteSource{Kind: "HTTPRoute", Name: "api", Rule: 0}, ok: true},
		{name: "per host copy", in: "httproute/ns/api/rule/1/match/0/www_example_com", want: RouteSource{Kind: "HTTPRoute", Namespace: "ns", Name: "api", Rule: 1}, ok: true},
		{name: "unknown kind", in: "tcproute/ns/db/rule/0/match/0", ok: false},
		{name: "too short", in: "httproute/ns/api", ok: false},
		{name: "wrong markers", in: "httproute/ns/api/rules/0/matches/0", ok: false},
		{name: "non numeric rule", in: "httproute/ns/api/rule/x/match/0", ok: false},
		{name: "empty", in: "", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseRouteName(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseListenerName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want ListenerSource
		ok   bool
	}{
		{name: "listener", in: "ns/prod/https", want: ListenerSource{Namespace: "ns", Gateway: "prod", Section: "https"}, ok: true},
		{name: "no namespace", in: "/default/http", want: ListenerSource{Gateway: "default", Section: "http"}, ok: true},
		{name: "missing section", in: "ns/prod", ok: false},
		{name: "empty gateway", in: "ns//https", ok: false},
		{name: "too many segments", in: "ns/prod/https/extra", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseListenerName(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
