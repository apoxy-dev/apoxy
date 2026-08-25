// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"capnproto.org/go/capnp/v3"
	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	workerdconfig "github.com/apoxy-dev/apoxy/pkg/workerd/config"
)

func mod(name string, typ computev1alpha1.ModuleType, path string) computev1alpha1.Module {
	return computev1alpha1.Module{Name: name, Type: typ, Path: path}
}

func decodeWorkerdConfig(t *testing.T, raw []byte) workerdconfig.Config {
	t.Helper()
	msg, err := capnp.Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal workerd config: %v", err)
	}
	t.Cleanup(msg.Release)
	cfg, err := workerdconfig.ReadRootConfig(msg)
	if err != nil {
		t.Fatalf("read workerd config: %v", err)
	}
	return cfg
}

func textListValues(t *testing.T, list capnp.TextList) []string {
	t.Helper()
	out := make([]string, list.Len())
	for i := range out {
		value, err := list.At(i)
		if err != nil {
			t.Fatalf("read text list item %d: %v", i, err)
		}
		out[i] = value
	}
	return out
}

func TestBuildResidentConfig(t *testing.T) {
	cases := []struct {
		name    string
		in      ResidentConfigInput
		wantErr bool
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
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := BuildResidentConfig(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertResidentConfig(t, decodeWorkerdConfig(t, raw), tc.in)
		})
	}
}

func assertResidentConfig(t *testing.T, cfg workerdconfig.Config, in ResidentConfigInput) {
	t.Helper()
	services, err := cfg.Services()
	if err != nil {
		t.Fatalf("read services: %v", err)
	}
	if services.Len() != 3 {
		t.Fatalf("services len = %d, want 3", services.Len())
	}

	dispatcherService := services.At(0)
	name, _ := dispatcherService.Name()
	if name != dispatcherServiceName || dispatcherService.Which().String() != "worker" {
		t.Fatalf("dispatcher service = name %q kind %q", name, dispatcherService.Which())
	}
	dispatcher, err := dispatcherService.Worker()
	if err != nil {
		t.Fatalf("read dispatcher worker: %v", err)
	}
	compatDate, _ := dispatcher.CompatibilityDate()
	if compatDate != dispatcherCompatDate {
		t.Errorf("dispatcher compatibility date = %q, want %q", compatDate, dispatcherCompatDate)
	}
	flags, err := dispatcher.CompatibilityFlags()
	if err != nil {
		t.Fatalf("read dispatcher flags: %v", err)
	}
	if got := strings.Join(textListValues(t, flags), ","); got != experimentalFlag {
		t.Errorf("dispatcher flags = %q, want %q", got, experimentalFlag)
	}
	modules, err := dispatcher.Modules()
	if err != nil {
		t.Fatalf("read dispatcher modules: %v", err)
	}
	if modules.Len() != 1 {
		t.Fatalf("dispatcher modules len = %d, want 1", modules.Len())
	}
	dispatcherModule := modules.At(0)
	moduleName, _ := dispatcherModule.Name()
	source, _ := dispatcherModule.EsModule()
	if moduleName != dispatcherModuleName || dispatcherModule.Which().String() != "esModule" {
		t.Errorf("dispatcher module = name %q kind %q", moduleName, dispatcherModule.Which())
	}
	for _, want := range []string{"x-apoxy-service", "x-apoxy-revision", "env.LOADER.get"} {
		if !strings.Contains(source, want) {
			t.Errorf("dispatcher source missing %q", want)
		}
	}

	bindings, err := dispatcher.Bindings()
	if err != nil {
		t.Fatalf("read dispatcher bindings: %v", err)
	}
	if bindings.Len() != 3 {
		t.Fatalf("dispatcher bindings len = %d, want 3", bindings.Len())
	}
	assertBindingKind(t, bindings.At(0), loaderBindingName, "workerLoader", "")
	assertBindingKind(t, bindings.At(1), managerBindingName, "service", managerServiceName)
	assertBindingKind(t, bindings.At(2), globalOutboundBindingName, "service", globalOutboundServiceName)

	managerService := services.At(1)
	name, _ = managerService.Name()
	manager, err := managerService.External()
	if err != nil {
		t.Fatalf("read manager service: %v", err)
	}
	managerAddr, _ := manager.Address()
	if name != managerServiceName || managerService.Which().String() != "external" ||
		managerAddr != in.ManagerAddr || manager.Which().String() != "http" {
		t.Errorf("manager service = name %q kind %q address %q protocol %q",
			name, managerService.Which(), managerAddr, manager.Which())
	}

	// GLOBAL_OUTBOUND is structurally tied to a Network service. The generated
	// union makes the old address-carrying ExternalServer foot-gun impossible
	// without changing this construction.
	internetService := services.At(2)
	name, _ = internetService.Name()
	internet, err := internetService.Network()
	if err != nil {
		t.Fatalf("read global outbound network: %v", err)
	}
	allow, err := internet.Allow()
	if err != nil {
		t.Fatalf("read global outbound allow list: %v", err)
	}
	tls, err := internet.TlsOptions()
	if err != nil {
		t.Fatalf("read global outbound TLS options: %v", err)
	}
	if name != globalOutboundServiceName || internetService.Which().String() != "network" ||
		strings.Join(textListValues(t, allow), ",") != strings.Join(globalOutboundAllow, ",") ||
		!internet.HasTlsOptions() || !tls.TrustBrowserCas() {
		t.Errorf("global outbound = name %q kind %q allow %v hasTLS %v browserCAs %v",
			name, internetService.Which(), textListValues(t, allow), internet.HasTlsOptions(), tls.TrustBrowserCas())
	}

	sockets, err := cfg.Sockets()
	if err != nil {
		t.Fatalf("read sockets: %v", err)
	}
	if sockets.Len() != 1 {
		t.Fatalf("sockets len = %d, want 1", sockets.Len())
	}
	socket := sockets.At(0)
	socketName, _ := socket.Name()
	socketAddr, _ := socket.Address()
	target, err := socket.Service()
	if err != nil {
		t.Fatalf("read socket target: %v", err)
	}
	targetName, _ := target.Name()
	if socketName != httpSocketName || socketAddr != in.SocketAddr ||
		socket.Which().String() != "http" || targetName != dispatcherServiceName {
		t.Errorf("socket = name %q address %q kind %q target %q",
			socketName, socketAddr, socket.Which(), targetName)
	}
}

func assertBindingKind(
	t *testing.T,
	binding workerdconfig.Worker_Binding,
	wantName, wantKind, wantService string,
) {
	t.Helper()
	name, err := binding.Name()
	if err != nil {
		t.Fatalf("read binding name: %v", err)
	}
	if name != wantName || binding.Which().String() != wantKind {
		t.Errorf("binding = name %q kind %q, want name %q kind %q",
			name, binding.Which(), wantName, wantKind)
	}
	if wantService != "" {
		service, err := binding.Service()
		if err != nil {
			t.Fatalf("read service binding %q: %v", name, err)
		}
		serviceName, _ := service.Name()
		if serviceName != wantService {
			t.Errorf("binding %q target = %q, want %q", name, serviceName, wantService)
		}
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
		if !bytes.Equal(again, first) {
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
