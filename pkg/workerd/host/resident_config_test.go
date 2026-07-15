// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"encoding/json"
	"strings"
	"testing"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

func TestBuildResidentConfig(t *testing.T) {
	cases := []struct {
		name     string
		in       ResidentConfigInput
		wantErr  bool
		wantSubs []string
	}{
		{
			name:    "missing socket addr",
			in:      ResidentConfigInput{ManagerAddr: "unix:/run/c.sock"},
			wantErr: true,
		},
		{
			name:    "missing manager addr",
			in:      ResidentConfigInput{SocketAddr: "*:8080"},
			wantErr: true,
		},
		{
			name: "full resident config",
			in:   ResidentConfigInput{SocketAddr: "unix:/run/in.sock", ManagerAddr: "unix:/run/control.sock"},
			wantSubs: []string{
				`(name = "dispatcher", worker = .dispatcher),`,
				`(name = "manager", external = (address = "unix:/run/control.sock", http = ())),`,
				// globalOutbound is a Network service (structural egress, §2.8):
				`(name = "internet", network = (allow = ["public", "private", "local", "network"])),`,
				`(name = "http", address = "unix:/run/in.sock", http = (), service = "dispatcher"),`,
				`compatibilityFlags = ["experimental"],`,
				`(name = "LOADER", workerLoader = ()),`,
				`(name = "MANAGER", service = "manager"),`,
				`(name = "GLOBAL_OUTBOUND", service = "internet"),`,
				// the dispatcher source is inlined (not embed):
				`x-apoxy-service`,
				`env.LOADER.get`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildResidentConfig(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (output:\n%s)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, s := range tc.wantSubs {
				if !strings.Contains(got, s) {
					t.Errorf("output missing %q:\n%s", s, got)
				}
			}
			// The dispatcher must be inlined, never an embed path (no second file
			// is staged next to the resident config).
			if strings.Contains(got, "esModule = embed") {
				t.Errorf("resident config should inline the dispatcher, not embed it:\n%s", got)
			}
		})
	}
}

// TestValidateGlobalOutbound is the §2.8 structural-egress guard: the service
// backing GLOBAL_OUTBOUND (hence every isolate's globalOutbound) must be a
// `network` service, never an address-carrying `external` one that would flatten
// every destination before any syscall and blind the in-Sentry forwarder. The
// real emission is checked by BuildResidentConfig's self-check (below); these
// hand-crafted configs prove the guard rejects the foot-gun forms.
func TestValidateGlobalOutbound(t *testing.T) {
	// realEmitted is the actual output — the guard must accept it.
	realEmitted, err := BuildResidentConfig(ResidentConfigInput{
		SocketAddr: "*:8080", ManagerAddr: "unix:/run/control.sock",
	})
	if err != nil {
		t.Fatalf("BuildResidentConfig: %v", err)
	}

	cases := []struct {
		name       string
		cfg        string
		wantErrSub string
	}{
		{
			name: "real emitted config passes",
			cfg:  realEmitted,
		},
		{
			name: "network service is accepted",
			cfg: `(name = "internet", network = (allow = ["public"])),` +
				`(name = "GLOBAL_OUTBOUND", service = "internet"),`,
		},
		{
			name: "external service is the foot-gun",
			cfg: `(name = "internet", external = (address = "10.0.0.1:9999", http = ())),` +
				`(name = "GLOBAL_OUTBOUND", service = "internet"),`,
			wantErrSub: "must resolve to a `network` service",
		},
		{
			name: "unix-socket external is the foot-gun",
			cfg: `(name = "proxy", external = (address = "unix:/run/proxy.sock", http = ())),` +
				`(name = "GLOBAL_OUTBOUND", service = "proxy"),`,
			wantErrSub: "must resolve to a `network` service",
		},
		{
			name: "loopback external is the foot-gun",
			cfg: `(name = "proxy", external = (address = "127.0.0.1:1080", http = ())),` +
				`(name = "GLOBAL_OUTBOUND", service = "proxy"),`,
			wantErrSub: "must resolve to a `network` service",
		},
		{
			name: "worker service is not structural egress",
			cfg: `(name = "sink", worker = .sink),` +
				`(name = "GLOBAL_OUTBOUND", service = "sink"),`,
			wantErrSub: "must resolve to a `network` service",
		},
		{
			name:       "missing binding is dead egress",
			cfg:        `(name = "internet", network = (allow = ["public"])),`,
			wantErrSub: "has no GLOBAL_OUTBOUND binding",
		},
		{
			name: "binding to undefined service",
			cfg: `(name = "GLOBAL_OUTBOUND", service = "ghost"),` +
				`(name = "internet", network = (allow = ["public"])),`,
			wantErrSub: `undefined service "ghost"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGlobalOutbound(tc.cfg)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErrSub)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrSub)
			}
		})
	}
}

func TestBuildResidentConfig_Deterministic(t *testing.T) {
	in := ResidentConfigInput{SocketAddr: "*:8080", ManagerAddr: "unix:/run/control.sock"}
	first, err := BuildResidentConfig(in)
	if err != nil {
		t.Fatalf("BuildResidentConfig: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := BuildResidentConfig(in)
		if err != nil {
			t.Fatalf("BuildResidentConfig (run %d): %v", i, err)
		}
		if again != first {
			t.Fatalf("non-deterministic output on run %d", i)
		}
	}
}

func src(pairs ...string) map[string][]byte {
	m := make(map[string][]byte)
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = []byte(pairs[i+1])
	}
	return m
}

func TestBuildWorkerDefinition(t *testing.T) {
	esOnly := []computev1alpha1.Module{mod("index.js", computev1alpha1.ESModule, "index.js")}

	cases := []struct {
		name       string
		manifest   computev1alpha1.BundleManifest
		cfg        computev1alpha1.ServiceConfigSpec
		source     map[string][]byte
		secrets    map[string]string
		wantErrSub string
		assert     func(t *testing.T, def WorkerDefinition)
	}{
		{
			name:     "happy esModule entrypoint",
			manifest: computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01", CompatibilityFlags: []string{"nodejs_compat"}},
			cfg:      computev1alpha1.ServiceConfigSpec{Env: []computev1alpha1.EnvVar{{Name: "API_URL", Value: "https://x"}}},
			source:   src("index.js", "export default {}"),
			assert: func(t *testing.T, def WorkerDefinition) {
				if def.MainModule != "index.js" {
					t.Errorf("mainModule = %q, want index.js", def.MainModule)
				}
				if def.CompatibilityDate != "2024-01-01" {
					t.Errorf("compatDate = %q", def.CompatibilityDate)
				}
				if def.Env["API_URL"] != "https://x" {
					t.Errorf("env = %+v", def.Env)
				}
				if got := def.Modules["index.js"]; got.kind != computev1alpha1.ESModule || got.body != "export default {}" {
					t.Errorf("module = %+v", got)
				}
			},
		},
		{
			name:     "runtime compatibilityDate overrides manifest",
			manifest: computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01"},
			cfg:      computev1alpha1.ServiceConfigSpec{Runtime: &computev1alpha1.ServiceRuntime{CompatibilityDate: "2025-06-01"}},
			source:   src("index.js", "x"),
			assert: func(t *testing.T, def WorkerDefinition) {
				if def.CompatibilityDate != "2025-06-01" {
					t.Errorf("compatDate = %q, want 2025-06-01", def.CompatibilityDate)
				}
			},
		},
		{
			name:     "flags union dedupes preserving order",
			manifest: computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01", CompatibilityFlags: []string{"a", "b"}},
			cfg:      computev1alpha1.ServiceConfigSpec{Runtime: &computev1alpha1.ServiceRuntime{CompatibilityFlags: []string{"b", "c"}}},
			source:   src("index.js", "x"),
			assert: func(t *testing.T, def WorkerDefinition) {
				if strings.Join(def.CompatibilityFlags, ",") != "a,b,c" {
					t.Errorf("flags = %v, want [a b c]", def.CompatibilityFlags)
				}
			},
		},
		{
			name:       "missing compatibility date",
			manifest:   computev1alpha1.BundleManifest{Modules: esOnly},
			source:     src("index.js", "x"),
			wantErrSub: "compatibilityDate is required",
		},
		{
			name:       "no esModule entrypoint",
			manifest:   computev1alpha1.BundleManifest{Modules: []computev1alpha1.Module{mod("d.txt", computev1alpha1.TextModule, "d.txt")}, CompatibilityDate: "2024-01-01"},
			source:     src("d.txt", "x"),
			wantErrSub: "no esModule entrypoint",
		},
		{
			name:       "kv binding unsupported",
			manifest:   computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01"},
			cfg:        computev1alpha1.ServiceConfigSpec{Bindings: []computev1alpha1.Binding{{Name: "DB", Type: computev1alpha1.KVBindingType}}},
			source:     src("index.js", "x"),
			wantErrSub: "not supported yet",
		},
		{
			name:     "secret binding resolved into env",
			manifest: computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01"},
			cfg: computev1alpha1.ServiceConfigSpec{
				Env: []computev1alpha1.EnvVar{{Name: "PLAIN", Value: "v"}},
				Bindings: []computev1alpha1.Binding{{
					Name: "API_TOKEN", Type: computev1alpha1.SecretBindingType,
					Secret: &computev1alpha1.SecretBinding{Store: "st", Key: "token"},
				}},
			},
			source:  src("index.js", "x"),
			secrets: map[string]string{"API_TOKEN": "s3cr3t"},
			assert: func(t *testing.T, def WorkerDefinition) {
				if def.Env["API_TOKEN"] != "s3cr3t" || def.Env["PLAIN"] != "v" {
					t.Errorf("env = %+v", def.Env)
				}
			},
		},
		{
			name:     "secret binding without resolved value",
			manifest: computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01"},
			cfg: computev1alpha1.ServiceConfigSpec{
				Bindings: []computev1alpha1.Binding{{
					Name: "API_TOKEN", Type: computev1alpha1.SecretBindingType,
					Secret: &computev1alpha1.SecretBinding{Store: "st", Key: "token"},
				}},
			},
			source:     src("index.js", "x"),
			wantErrSub: "no resolved value",
		},
		{
			name:     "secret binding collides with env var",
			manifest: computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01"},
			cfg: computev1alpha1.ServiceConfigSpec{
				Env: []computev1alpha1.EnvVar{{Name: "API_TOKEN", Value: "plain"}},
				Bindings: []computev1alpha1.Binding{{
					Name: "API_TOKEN", Type: computev1alpha1.SecretBindingType,
					Secret: &computev1alpha1.SecretBinding{Store: "st", Key: "token"},
				}},
			},
			source:     src("index.js", "x"),
			secrets:    map[string]string{"API_TOKEN": "s3cr3t"},
			wantErrSub: "collides with an env var",
		},
		{
			name:       "assets unsupported in dispatcher path",
			manifest:   computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01", AssetsPrefix: "/static"},
			source:     src("index.js", "x"),
			wantErrSub: "assets are not yet supported",
		},
		{
			name:       "binary module unsupported",
			manifest:   computev1alpha1.BundleManifest{Modules: []computev1alpha1.Module{mod("index.js", computev1alpha1.ESModule, "index.js"), mod("m.wasm", computev1alpha1.WasmModule, "m.wasm")}, CompatibilityDate: "2024-01-01"},
			source:     src("index.js", "x", "m.wasm", "\x00asm"),
			wantErrSub: "binary module type",
		},
		{
			name:       "missing module source",
			manifest:   computev1alpha1.BundleManifest{Modules: esOnly, CompatibilityDate: "2024-01-01"},
			source:     src(),
			wantErrSub: "missing source for module",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, err := BuildWorkerDefinition(tc.manifest, tc.cfg, tc.source, tc.secrets)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantErrSub)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.assert != nil {
				tc.assert(t, def)
			}
		})
	}
}

// TestBuildWorkerDefinition_EntrypointFirst asserts the first esModule becomes
// mainModule even when it is not first in the manifest.
func TestBuildWorkerDefinition_EntrypointFirst(t *testing.T) {
	def, err := BuildWorkerDefinition(
		computev1alpha1.BundleManifest{
			Modules: []computev1alpha1.Module{
				mod("a.txt", computev1alpha1.TextModule, "a.txt"),
				mod("main.js", computev1alpha1.ESModule, "main.js"),
			},
			CompatibilityDate: "2024-01-01",
		},
		computev1alpha1.ServiceConfigSpec{},
		src("a.txt", "hello", "main.js", "export default {}"),
		nil,
	)
	if err != nil {
		t.Fatalf("BuildWorkerDefinition: %v", err)
	}
	if def.MainModule != "main.js" {
		t.Errorf("mainModule = %q, want main.js", def.MainModule)
	}
	if def.Modules["a.txt"].kind != computev1alpha1.TextModule {
		t.Errorf("a.txt kind = %q, want text", def.Modules["a.txt"].kind)
	}
}

// TestWorkerDefinition_JSONShape locks the WorkerCode wire shape the dispatcher's
// WorkerLoader callback consumes. The 796-0 de-risking spike validated this exact
// shape against stock workerd; the in-tree end-to-end proof is the linux
// acceptance test.
func TestWorkerDefinition_JSONShape(t *testing.T) {
	def, err := BuildWorkerDefinition(
		computev1alpha1.BundleManifest{
			Modules:            []computev1alpha1.Module{mod("index.js", computev1alpha1.ESModule, "index.js")},
			CompatibilityDate:  "2025-06-01",
			CompatibilityFlags: []string{"nodejs_compat"},
		},
		computev1alpha1.ServiceConfigSpec{Env: []computev1alpha1.EnvVar{{Name: "K", Value: "v"}}},
		src("index.js", "export default { fetch(){ return new Response('hi') } }"),
		nil,
	)
	if err != nil {
		t.Fatalf("BuildWorkerDefinition: %v", err)
	}
	b, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		`"compatibilityDate":"2025-06-01"`,
		`"compatibilityFlags":["nodejs_compat"]`,
		`"mainModule":"index.js"`,
		`"modules":{"index.js":{"js":"export default { fetch(){ return new Response('hi') } }"}}`,
		`"env":{"K":"v"}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON missing %s:\n%s", want, got)
		}
	}
}
