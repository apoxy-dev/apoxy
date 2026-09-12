// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	ratelimitv3 "github.com/envoyproxy/go-control-plane/ratelimit/config/ratelimit/v3"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	xdsutils "github.com/apoxy-dev/apoxy/pkg/gateway/xds/utils"
)

// The xDS IR inputs come from Envoy Gateway.
//
// testdata/in/extension-xds-ir has no test. Envoy Gateway drove it with an
// in-process extension manager, and this fork calls an extension server over
// gRPC instead.

// overrideTestData rewrites the golden files instead of comparing them.
var overrideTestData = flag.Bool("override-testdata", false, "if override the test output data.")

const defaultDNSDomain = "cluster.local"

// negativeXdsIR names the inputs that must fail translation.
var negativeXdsIR = map[string]bool{
	"accesslog-invalid":          true,
	"http-route-invalid":         true,
	"tcp-route-invalid":          true,
	"tcp-route-invalid-endpoint": true,
	"tracing-invalid":            true,
	"udp-route-invalid":          true,
}

// skippedXdsIR names the inputs this fork cannot translate, with the reason.
var skippedXdsIR = map[string]string{
	// The IR holds the json patches on a type this fork does not read.
	"jsonpatch":                      "this fork does not translate EnvoyPatchPolicy",
	"jsonpatch-add-op-without-value": "this fork does not translate EnvoyPatchPolicy",
	"jsonpatch-invalid":              "this fork does not translate EnvoyPatchPolicy",
	"jsonpatch-invalid-listener":     "this fork does not translate EnvoyPatchPolicy",
	"jsonpatch-invalid-patch":        "this fork does not translate EnvoyPatchPolicy",
	"jsonpatch-missing-resource":     "this fork does not translate EnvoyPatchPolicy",
	"jsonpatch-move-op-with-value":   "this fork does not translate EnvoyPatchPolicy",

	// These two inputs come from a later Envoy Gateway than this fork's IR.
	"mixed-tls-jwt-authn": "input puts a TLS list on the HTTP listener, the IR holds one TLS config",
	"tracing":             "input predates the tracing provider type and destination fields in the IR",
}

// dnsDomains overrides the cluster DNS domain per input.
var dnsDomains = map[string]string{
	"ratelimit-custom-domain": "example-cluster.local",
}

// TestTranslateXds translates every xDS IR input and compares each resource
// type against its golden file.
func TestTranslateXds(t *testing.T) {
	for _, name := range testDataInputNames(t, "xds-ir") {
		t.Run(name, func(t *testing.T) {
			if reason, ok := skippedXdsIR[name]; ok {
				t.Skip(reason)
			}

			xdsIR := requireXdsIRFromInputTestData(t, "xds-ir", name+".yaml")
			tr := newGoldenTranslator(name)

			tCtx, err := tr.Translate(xdsIR)
			if negativeXdsIR[name] {
				require.Error(t, err)
				require.Contains(t, err.Error(), "validation failed for xds resource")
				return
			}
			// Inputs named "*-partial-invalid" translate the valid part and
			// report the rest as an error.
			if !strings.HasSuffix(name, "partial-invalid") {
				require.NoError(t, err)
			}

			resources := []struct {
				suffix string
				res    []cachetypes.Resource
			}{
				{"listeners", tCtx.XdsResources[resourcev3.ListenerType]},
				{"routes", tCtx.XdsResources[resourcev3.RouteType]},
				{"clusters", tCtx.XdsResources[resourcev3.ClusterType]},
				{"endpoints", tCtx.XdsResources[resourcev3.EndpointType]},
				{"secrets", tCtx.XdsResources[resourcev3.SecretType]},
			}
			for _, r := range resources {
				golden := filepath.Join("testdata", "out", "xds-ir", name+"."+r.suffix+".yaml")
				// Only inputs that carry certificates have a secrets golden.
				if r.suffix == "secrets" && len(r.res) == 0 && !fileExists(golden) {
					continue
				}
				requireGoldenMatch(t, golden, requireResourcesToYAMLString(t, r.res))
			}
		})
	}
}

// TestTranslateRateLimitConfig builds the rate limit service configuration for
// every listener input and compares it against its golden file.
func TestTranslateRateLimitConfig(t *testing.T) {
	for _, name := range testDataInputNames(t, "ratelimit-config") {
		t.Run(name, func(t *testing.T) {
			in := requireXdsIRListenerFromInputTestData(t, "ratelimit-config", name+".yaml")
			out := BuildRateLimitServiceConfig(in)
			golden := filepath.Join("testdata", "out", "ratelimit-config", name+".yaml")
			requireGoldenMatch(t, golden, requireYamlRootToYAMLString(t, out))
		})
	}
}

func newGoldenTranslator(name string) *Translator {
	dnsDomain := dnsDomains[name]
	if dnsDomain == "" {
		dnsDomain = defaultDNSDomain
	}
	return &Translator{
		GlobalRateLimit: &GlobalRateLimitSettings{
			ServiceURL: fmt.Sprintf("grpc://envoy-ratelimit.envoy-gateway-system.svc.%s:8081", dnsDomain),
		},
	}
}

// testDataInputNames returns the sorted base names of the inputs in dir.
func testDataInputNames(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "in", dir, "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	names := make([]string, 0, len(paths))
	for _, p := range paths {
		names = append(names, strings.TrimSuffix(filepath.Base(p), ".yaml"))
	}
	slices.Sort(names)
	return names
}

func requireXdsIRFromInputTestData(t *testing.T, name ...string) *ir.Xds {
	t.Helper()
	elems := append([]string{"testdata", "in"}, name...)
	content, err := os.ReadFile(filepath.Join(elems...))
	require.NoError(t, err)
	xdsIR := &ir.Xds{}
	require.NoError(t, yaml.Unmarshal(content, xdsIR))
	return xdsIR
}

func requireXdsIRListenerFromInputTestData(t *testing.T, name ...string) *ir.HTTPListener {
	t.Helper()
	elems := append([]string{"testdata", "in"}, name...)
	content, err := os.ReadFile(filepath.Join(elems...))
	require.NoError(t, err)
	listener := &ir.HTTPListener{}
	require.NoError(t, yaml.Unmarshal(content, listener))
	return listener
}

// requireGoldenMatch compares got against the golden file, or rewrites the
// golden file when -override-testdata is set.
func requireGoldenMatch(t *testing.T, path, got string) {
	t.Helper()
	if *overrideTestData {
		// nolint:gosec
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), got, "golden file %s is out of date, rerun with -override-testdata", path)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func requireYamlRootToYAMLString(t *testing.T, pbRoot *ratelimitv3.RateLimitConfig) string {
	t.Helper()
	str, err := GetRateLimitServiceConfigStr(pbRoot)
	require.NoError(t, err)
	return str
}

func requireResourcesToYAMLString(t *testing.T, resources []cachetypes.Resource) string {
	t.Helper()
	str, err := xdsutils.ResourcesToYAMLString(resources)
	require.NoError(t, err)
	return str
}
