package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadIMDS(t *testing.T) {
	facts := map[string]string{
		"/latest/meta-data/instance-id":                 "i-0abc",
		"/latest/meta-data/instance-type":               "c7a.8xlarge",
		"/latest/meta-data/placement/availability-zone": "us-west-2a",
		"/latest/meta-data/ami-id":                      "ami-0123",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/api/token" {
			if r.Method != http.MethodPut || r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				http.Error(w, "bad token request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("tok"))
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "tok" {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		v, ok := facts[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(v + "\n"))
	}))
	defer srv.Close()

	got, err := readIMDS(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, &EC2{InstanceID: "i-0abc", InstanceType: "c7a.8xlarge", AZ: "us-west-2a", AMI: "ami-0123"}, got)

	delete(facts, "/latest/meta-data/ami-id")
	_, err = readIMDS(context.Background(), srv.URL)
	require.ErrorContains(t, err, "read ami-id")
}

func TestSysctlPath(t *testing.T) {
	cases := []struct{ key, want string }{
		{"net.core.rmem_max", "/proc/sys/net/core/rmem_max"},
		{"net.ipv4.tcp_rmem", "/proc/sys/net/ipv4/tcp_rmem"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			assert.Equal(t, tc.want, sysctlPath(tc.key))
		})
	}
}
