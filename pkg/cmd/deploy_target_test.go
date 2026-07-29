package cmd

import "testing"

func TestFormatDeployTarget(t *testing.T) {
	const (
		id  = "3340b6b9-585d-4ecd-8703-5f309a46562d"
		url = "https://api-staging.apoxy.dev"
	)
	cases := []struct {
		name  string
		pname string
		env   string
		want  string
	}{
		{name: "name and env", pname: "acme-api", env: "staging", want: `project "acme-api" (staging)`},
		{name: "name only", pname: "acme-api", want: `project "acme-api" at ` + url},
		{name: "env only", env: "staging", want: "project " + id + " (staging)"},
		{name: "neither", want: "project " + id + " at " + url},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatDeployTarget(tc.pname, tc.env, id, url); got != tc.want {
				t.Errorf("formatDeployTarget = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnvLabelForAPI(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{host: "api.apoxy.dev", want: "production"},
		{host: "api-staging.apoxy.dev", want: "staging"},
		{host: "api.apoxy.localhost", want: "local dev"},
		{host: "localhost", want: ""},
		{host: "apiz.customer.example.com", want: ""},
	}
	for _, tc := range cases {
		if got := envLabelForAPI(tc.host); got != tc.want {
			t.Errorf("envLabelForAPI(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}
