// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"capnproto.org/go/capnp/v3"
	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	workerdconfig "github.com/apoxy-dev/apoxy/pkg/workerd/config"
)

// httpSocketName is the workerd socket name for the resident's HTTP socket.
const httpSocketName = "http"

var (
	errNoCompatibilityDate = errors.New("workerd-host: compatibilityDate is required (workerd refuses to start without it)")
	errNoEntrypoint        = errors.New("workerd-host: bundle has no esModule entrypoint module")
)

func setTextList(list capnp.TextList, values []string) error {
	for i, value := range values {
		if err := list.Set(i, value); err != nil {
			return err
		}
	}
	return nil
}

// The resident model runs one static dispatcher worker per tenant and loads
// customer isolates at runtime. BuildResidentConfig builds the dispatcher's
// static workerd config; BuildWorkerDefinition builds the per-isolate
// WorkerCode payload served through WorkerLoader.

// dispatcherJS is the static dispatcher worker source, inlined into the
//
//go:embed dispatcher.js
var dispatcherJS string

const (
	// dispatcherServiceName is the workerd service name for the dispatcher.
	dispatcherServiceName = "dispatcher"
	// managerServiceName is the workerd (external) service the dispatcher's
	// WorkerLoader callback fetches worker definitions from.
	managerServiceName = "manager"
	// loaderBindingName is the WorkerLoader binding env name (env.LOADER).
	loaderBindingName = "LOADER"
	// managerBindingName is the service binding env name (env.MANAGER).
	managerBindingName = "MANAGER"
	// dispatcherModuleName is the dispatcher's single module name.
	dispatcherModuleName = "dispatcher.js"
	// dispatcherCompatDate pins the dispatcher's own compatibility date. It is
	// independent of any customer worker's compatibilityDate.
	dispatcherCompatDate = "2025-06-01"
	// experimentalFlag is required to enable the workerLoader binding.
	experimentalFlag = "experimental"
	// globalOutboundServiceName is the workerd Network service that backs every
	// isolate's globalOutbound (the dispatcher passes the GLOBAL_OUTBOUND binding
	// to each WorkerLoader isolate). A `network` service means workerd runs its
	// own getaddrinfo + socket()/connect() for fetch() — a real, structural egress
	// the in-Sentry forwarder catches with the true (src,dst) and the host egress
	// bridge mediates. It must NEVER be an `external` service (one carrying an
	// address workerd dials directly): that flattens every destination to a single
	// endpoint before any syscall, blinding the forwarder. See
	// workerd-egress-encap.mdx §2.8.
	globalOutboundServiceName = "internet"
	// globalOutboundBindingName is the dispatcher env binding (env.GLOBAL_OUTBOUND)
	// the WorkerLoader callback passes as each isolate's globalOutbound.
	globalOutboundBindingName = "GLOBAL_OUTBOUND"
)

// globalOutboundAllow is the Network service allow set. It is deliberately broad:
// the host egress bridge — not workerd's own network filter — is the egress
// policy authority (allow/deny/SSRF/gateway/direct), and workerd must actually
// issue the connect() for the in-Sentry forwarder to catch and mediate it.
// Narrowing this would let workerd pre-empt a syscall the bridge needs to see.
// This exact set is validated end-to-end against stock workerd by the linux
// acceptance test (a real fetch() connect() caught by the forwarder).
var globalOutboundAllow = []string{"public", "private", "local", "network"}

// Naming the service "internet" suppresses the implicit one workerd would
// otherwise synthesize, and that implicit service is the only thing that sets
// useSystemTrustStore. The structured config therefore explicitly enables
// trustBrowserCas on the Network service's TLS options.
//
// This is a plain TLS client config, not interception: on the direct-dial path
// the bridge splices bytes, so workerd terminates TLS against the real origin
// and validates the origin's own certificate. If EgressGateway routing (Envoy
// MITM, see egress_bridge.go) is ever wired up, the gateway's CA has to reach
// the worker too — as trustedCertificates here, since the MITM leaf will not
// chain to a browser CA.

// ResidentConfigInput is the input to BuildResidentConfig.
type ResidentConfigInput struct {
	// SocketAddr is the address the dispatcher's http socket binds — where the
	// inbound forwarder (APO-694) delivers Envoy's requests. workerd syntax:
	// "*:8080", "127.0.0.1:8080", or "unix:/path.sock".
	SocketAddr string
	// ManagerAddr is the in-sandbox address of the manager service the dispatcher
	// fetches worker definitions from through the control forwarder.
	ManagerAddr string
}

// BuildResidentConfig builds the static binary Cap'n Proto config for the one
// resident workerd: a single dispatcher worker (WorkerLoader + manager service
// binding) behind the HTTP socket. Pure and deterministic.
func BuildResidentConfig(in ResidentConfigInput) ([]byte, error) {
	if in.SocketAddr == "" {
		return nil, fmt.Errorf("workerd-host: resident config requires SocketAddr")
	}
	if in.ManagerAddr == "" {
		return nil, fmt.Errorf("workerd-host: resident config requires ManagerAddr")
	}

	msg, seg := capnp.NewSingleSegmentMessage(nil)
	defer msg.Release()
	cfg, err := workerdconfig.NewRootConfig(seg)
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating resident config: %w", err)
	}

	services, err := cfg.NewServices(3)
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating resident services: %w", err)
	}

	dispatcherService := services.At(0)
	if err := dispatcherService.SetName(dispatcherServiceName); err != nil {
		return nil, fmt.Errorf("workerd-host: setting dispatcher service name: %w", err)
	}
	dispatcher, err := dispatcherService.NewWorker()
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating dispatcher worker: %w", err)
	}
	if err := dispatcher.SetCompatibilityDate(dispatcherCompatDate); err != nil {
		return nil, fmt.Errorf("workerd-host: setting dispatcher compatibility date: %w", err)
	}
	flags, err := dispatcher.NewCompatibilityFlags(1)
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating dispatcher compatibility flags: %w", err)
	}
	if err := flags.Set(0, experimentalFlag); err != nil {
		return nil, fmt.Errorf("workerd-host: setting dispatcher compatibility flag: %w", err)
	}
	modules, err := dispatcher.NewModules(1)
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating dispatcher modules: %w", err)
	}
	dispatcherModule := modules.At(0)
	if err := dispatcherModule.SetName(dispatcherModuleName); err != nil {
		return nil, fmt.Errorf("workerd-host: setting dispatcher module name: %w", err)
	}
	if err := dispatcherModule.SetEsModule(dispatcherJS); err != nil {
		return nil, fmt.Errorf("workerd-host: setting dispatcher module source: %w", err)
	}
	dispatcherBindings, err := dispatcher.NewBindings(3)
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating dispatcher bindings: %w", err)
	}
	loader := dispatcherBindings.At(0)
	if err := loader.SetName(loaderBindingName); err != nil {
		return nil, fmt.Errorf("workerd-host: setting loader binding name: %w", err)
	}
	loader.SetWorkerLoader()
	if err := setServiceBinding(dispatcherBindings.At(1), managerBindingName, managerServiceName); err != nil {
		return nil, err
	}
	// The service union makes the structural-egress invariant explicit:
	// GLOBAL_OUTBOUND resolves to the Network service below, never an
	// address-carrying ExternalServer.
	if err := setServiceBinding(dispatcherBindings.At(2), globalOutboundBindingName, globalOutboundServiceName); err != nil {
		return nil, err
	}

	managerService := services.At(1)
	if err := managerService.SetName(managerServiceName); err != nil {
		return nil, fmt.Errorf("workerd-host: setting manager service name: %w", err)
	}
	manager, err := managerService.NewExternal()
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating manager service: %w", err)
	}
	if err := manager.SetAddress(in.ManagerAddr); err != nil {
		return nil, fmt.Errorf("workerd-host: setting manager address: %w", err)
	}
	if _, err := manager.NewHttp(); err != nil {
		return nil, fmt.Errorf("workerd-host: allocating manager HTTP options: %w", err)
	}

	internetService := services.At(2)
	if err := internetService.SetName(globalOutboundServiceName); err != nil {
		return nil, fmt.Errorf("workerd-host: setting global outbound service name: %w", err)
	}
	internet, err := internetService.NewNetwork()
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating global outbound network: %w", err)
	}
	allow, err := internet.NewAllow(int32(len(globalOutboundAllow)))
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating global outbound allow list: %w", err)
	}
	if err := setTextList(allow, globalOutboundAllow); err != nil {
		return nil, fmt.Errorf("workerd-host: setting global outbound allow list: %w", err)
	}
	tls, err := internet.NewTlsOptions()
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating global outbound TLS options: %w", err)
	}
	tls.SetTrustBrowserCas(true)

	sockets, err := cfg.NewSockets(1)
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating resident socket: %w", err)
	}
	socket := sockets.At(0)
	if err := socket.SetName(httpSocketName); err != nil {
		return nil, fmt.Errorf("workerd-host: setting resident socket name: %w", err)
	}
	if err := socket.SetAddress(in.SocketAddr); err != nil {
		return nil, fmt.Errorf("workerd-host: setting resident socket address: %w", err)
	}
	if _, err := socket.NewHttp(); err != nil {
		return nil, fmt.Errorf("workerd-host: allocating resident HTTP options: %w", err)
	}
	target, err := socket.NewService()
	if err != nil {
		return nil, fmt.Errorf("workerd-host: allocating resident socket service: %w", err)
	}
	if err := target.SetName(dispatcherServiceName); err != nil {
		return nil, fmt.Errorf("workerd-host: setting resident socket service: %w", err)
	}

	raw, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("workerd-host: marshaling resident config: %w", err)
	}
	return raw, nil
}

func setServiceBinding(binding workerdconfig.Worker_Binding, name, serviceName string) error {
	if err := binding.SetName(name); err != nil {
		return fmt.Errorf("workerd-host: setting binding %q name: %w", name, err)
	}
	service, err := binding.NewService()
	if err != nil {
		return fmt.Errorf("workerd-host: allocating service binding %q: %w", name, err)
	}
	if err := service.SetName(serviceName); err != nil {
		return fmt.Errorf("workerd-host: setting service binding %q: %w", name, err)
	}
	return nil
}

// WorkerDefinition is the per-isolate payload the manager serves to the
// dispatcher's WorkerLoader callback. It marshals to workerd's WorkerCode JSON
// shape: { compatibilityDate, compatibilityFlags, mainModule, modules, env }.
type WorkerDefinition struct {
	CompatibilityDate  string                   `json:"compatibilityDate"`
	CompatibilityFlags []string                 `json:"compatibilityFlags,omitempty"`
	MainModule         string                   `json:"mainModule"`
	Modules            map[string]moduleContent `json:"modules"`
	Env                map[string]string        `json:"env,omitempty"`
}

// moduleContent marshals to the WorkerLoader runtime module shape — a single-key
// object keyed by the WorkerLoader JS module kind, e.g. {"js": "<source>"}.
//
// NOTE: the WorkerLoader *runtime* `modules` map keys ("js"/"cjs"/"text"/"data"/
// "json"/"wasm") differ from the Cap'n Proto Worker.Module union field names
// ("esModule"/"commonJsModule"/...). This path must emit the WorkerLoader names.
// The 796-0 de-risking spike confirmed
// against stock workerd that a module emitted with the capnp "esModule" key is
// rejected by the runtime loader ("must contain exactly one of 'js', 'cjs',
// 'text', 'data', 'json', 'py', or 'wasm'"); the in-tree end-to-end proof is the
// linux acceptance test, not a committed spike artifact.
type moduleContent struct {
	kind computev1alpha1.ModuleType
	body string
}

func (m moduleContent) MarshalJSON() ([]byte, error) {
	key, ok := workerLoaderModuleKey(m.kind)
	if !ok {
		return nil, fmt.Errorf("workerd-host: module kind %q has no WorkerLoader key", m.kind)
	}
	return json.Marshal(map[string]string{key: m.body})
}

// workerLoaderModuleKey maps a compute ModuleType to the WorkerLoader runtime
// module-map key.
func workerLoaderModuleKey(t computev1alpha1.ModuleType) (string, bool) {
	switch t {
	case computev1alpha1.ESModule:
		return "js", true
	case computev1alpha1.CommonJSModule:
		return "cjs", true
	case computev1alpha1.TextModule:
		return "text", true
	case computev1alpha1.JSONModule:
		return "json", true
	case computev1alpha1.DataModule:
		return "data", true
	case computev1alpha1.WasmModule:
		return "wasm", true
	}
	return "", false
}

var errAssetsUnsupportedInDispatcher = errors.New("workerd-host: static assets are not yet supported in the dispatcher WorkerLoader path")

// BuildWorkerDefinition renders the WorkerCode payload for one ServiceRevision.
// source maps each Module.Name to its raw bytes (read from the extracted bundle
// by the manager); BuildWorkerDefinition stays pure and filesystem-free so it is
// table-testable. The first esModule is the entrypoint (mainModule).
// secrets maps secret-binding names to their resolved values.
func BuildWorkerDefinition(
	manifest computev1alpha1.BundleManifest,
	cfg computev1alpha1.ServiceConfigSpec,
	source map[string][]byte,
	secrets map[string]string,
) (WorkerDefinition, error) {
	compatDate := manifest.CompatibilityDate
	if cfg.Runtime != nil && cfg.Runtime.CompatibilityDate != "" {
		compatDate = cfg.Runtime.CompatibilityDate
	}
	if compatDate == "" {
		return WorkerDefinition{}, errNoCompatibilityDate
	}
	if manifest.AssetsPrefix != "" {
		return WorkerDefinition{}, errAssetsUnsupportedInDispatcher
	}

	modules, err := orderModules(manifest.Modules)
	if err != nil {
		return WorkerDefinition{}, err
	}

	env, err := buildEnvMap(cfg, secrets)
	if err != nil {
		return WorkerDefinition{}, err
	}

	out := WorkerDefinition{
		CompatibilityDate:  compatDate,
		CompatibilityFlags: unionFlags(manifest.CompatibilityFlags, runtimeFlags(cfg)),
		MainModule:         modules[0].Name,
		Modules:            make(map[string]moduleContent, len(modules)),
		Env:                env,
	}
	for _, m := range modules {
		body, ok := source[m.Name]
		if !ok {
			return WorkerDefinition{}, fmt.Errorf("workerd-host: missing source for module %q", m.Name)
		}
		mc, err := newModuleContent(m.Type, body)
		if err != nil {
			return WorkerDefinition{}, err
		}
		out.Modules[m.Name] = mc
	}
	return out, nil
}

// newModuleContent maps a module's bytes to its WorkerCode representation. The
// text-based kinds carry inline source; binary kinds (data/wasm) would need
// base64 transit plus dispatcher-side decoding and are deferred.
func newModuleContent(t computev1alpha1.ModuleType, body []byte) (moduleContent, error) {
	switch t {
	case computev1alpha1.ESModule, computev1alpha1.CommonJSModule,
		computev1alpha1.TextModule, computev1alpha1.JSONModule:
		return moduleContent{kind: t, body: string(body)}, nil
	case computev1alpha1.DataModule, computev1alpha1.WasmModule:
		return moduleContent{}, fmt.Errorf("workerd-host: binary module type %q is not yet supported in the dispatcher WorkerLoader path", t)
	default:
		return moduleContent{}, fmt.Errorf("workerd-host: unknown module type %q", t)
	}
}

// buildEnvMap materializes env vars and resolved secret bindings into the
// WorkerCode env object. kv/service bindings are not yet supported (APO-874)
// — encountering one is an explicit error, never a silent skip.
func buildEnvMap(cfg computev1alpha1.ServiceConfigSpec, secrets map[string]string) (map[string]string, error) {
	if len(cfg.Env) == 0 && len(cfg.Bindings) == 0 {
		return nil, nil
	}
	env := make(map[string]string, len(cfg.Env)+len(cfg.Bindings))
	for _, e := range cfg.Env {
		env[e.Name] = e.Value
	}
	for i := range cfg.Bindings {
		value, err := secretBindingValue(&cfg.Bindings[i], env, secrets)
		if err != nil {
			return nil, err
		}
		env[cfg.Bindings[i].Name] = value
	}
	return env, nil
}

// secretBindingValue resolves one binding to its env value: only secret
// bindings are supported, the caller must have supplied the resolved value,
// and the name must not collide with a plain env var.
func secretBindingValue(bd *computev1alpha1.Binding, env map[string]string, secrets map[string]string) (string, error) {
	if bd.Type != computev1alpha1.SecretBindingType {
		return "", fmt.Errorf("workerd-host: binding %q of type %q is not supported yet (kv/service bindings are APO-874)", bd.Name, bd.Type)
	}
	if bd.Secret == nil {
		return "", fmt.Errorf("workerd-host: secret binding %q has no secret block", bd.Name)
	}
	if _, dup := env[bd.Name]; dup {
		return "", fmt.Errorf("workerd-host: secret binding %q collides with an env var of the same name", bd.Name)
	}
	value, ok := secrets[bd.Name]
	if !ok {
		return "", fmt.Errorf("workerd-host: secret binding %q has no resolved value (store %q key %q)", bd.Name, bd.Secret.Store, bd.Secret.Key)
	}
	return value, nil
}

// orderModules validates module types and returns the modules with the first
// esModule moved to the front: workerd treats the first module in the list as
// the worker's entrypoint. Relative order of the remaining modules is
// preserved.
func orderModules(in []computev1alpha1.Module) ([]computev1alpha1.Module, error) {
	for _, m := range in {
		if !isSupportedModuleType(m.Type) {
			return nil, fmt.Errorf("workerd-host: module %q has unknown type %q", m.Name, m.Type)
		}
	}
	entry := -1
	for i, m := range in {
		if m.Type == computev1alpha1.ESModule {
			entry = i
			break
		}
	}
	if entry == -1 {
		return nil, errNoEntrypoint
	}
	out := make([]computev1alpha1.Module, 0, len(in))
	out = append(out, in[entry])
	for i, m := range in {
		if i == entry {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func isSupportedModuleType(t computev1alpha1.ModuleType) bool {
	switch t {
	case computev1alpha1.ESModule, computev1alpha1.CommonJSModule,
		computev1alpha1.TextModule, computev1alpha1.DataModule,
		computev1alpha1.JSONModule, computev1alpha1.WasmModule:
		return true
	default:
		return false
	}
}

func runtimeFlags(cfg computev1alpha1.ServiceConfigSpec) []string {
	if cfg.Runtime == nil {
		return nil
	}
	return cfg.Runtime.CompatibilityFlags
}

// unionFlags concatenates flag lists preserving first-seen order and dropping
// duplicates and empties.
func unionFlags(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, f := range l {
			if f == "" || seen[f] {
				continue
			}
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
