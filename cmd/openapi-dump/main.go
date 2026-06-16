// Command openapi-dump renders the apiserver's generated OpenAPI definitions to
// a static OpenAPI v3 JSON document offline — no running apiserver required.
//
// It exists so the console's openapi-typescript codegen (APO-765) is hermetic:
// CI regenerates console/openapi.json from api/generated/zz_generated.openapi.go
// and diffs it, instead of scraping /openapi/v3 from a live apiserver.
//
// Only components.schemas is emitted. The console builds requests from its GVR
// registry rather than from generated path operations, so the (large, dynamic)
// k8s path surface is intentionally omitted.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/validation/spec"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	coordinationv1 "github.com/apoxy-dev/apoxy/api/coordination/v1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	corev1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
	corev1alpha3 "github.com/apoxy-dev/apoxy/api/core/v1alpha3"
	extensionsv1alpha1 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha1"
	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	apoxyopenapi "github.com/apoxy-dev/apoxy/api/generated"
	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
	gatewayv1alpha2 "github.com/apoxy-dev/apoxy/api/gateway/v1alpha2"
	policyv1alpha1 "github.com/apoxy-dev/apoxy/api/policy/v1alpha1"
)

// buildScheme registers apoxy's own API types so the namer derives the same
// definition names the live apiserver serves. It mirrors the apoxy registrations
// in pkg/apiserver/manager.go init(), but deliberately omits that file's
// upstream gateway-api install (pkg/apiserver/gateway) — those types are not in
// the generated OpenAPI set, and the scheme only feeds the namer's GVK
// extensions, which this dump does not emit. Skipping it also avoids pulling the
// gateway controller's heavy transitive deps into a codegen tool.
func buildScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(computev1alpha1.Install(scheme))
	utilruntime.Must(corev1alpha.Install(scheme))
	utilruntime.Must(corev1alpha2.Install(scheme))
	utilruntime.Must(corev1alpha3.Install(scheme))
	utilruntime.Must(policyv1alpha1.Install(scheme))
	utilruntime.Must(extensionsv1alpha1.Install(scheme))
	utilruntime.Must(extensionsv1alpha2.Install(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(gatewayv1alpha2.Install(scheme))
	utilruntime.Must(coordinationv1.Install(scheme))
	return scheme
}

func main() {
	out := flag.String("o", "", "output file (default: stdout)")
	title := flag.String("title", "Apoxy API", "OpenAPI info.title")
	version := flag.String("version", "v0", "OpenAPI info.version")
	flag.Parse()

	namer := openapi.NewDefinitionNamer(buildScheme())

	// The ref callback and the schema map keys both run through namer, so every
	// generated $ref ("#/components/schemas/<name>") resolves to a real key.
	ref := func(name string) spec.Ref {
		defName, _ := namer.GetDefinitionName(name)
		return spec.MustCreateRef("#/components/schemas/" + common.EscapeJsonPointer(defName))
	}

	defs := apoxyopenapi.GetOpenAPIDefinitions(ref)
	schemas := make(map[string]spec.Schema, len(defs))
	for goPath, def := range defs {
		name, _ := namer.GetDefinitionName(goPath)
		schemas[name] = def.Schema
	}

	// Close dangling $refs. Some generated definitions depend on upstream types
	// (e.g. gateway-api ReferenceGrantSpec) for which apoxy's openapi-gen never
	// emitted a schema. The k8s spec builder tolerates these gaps; the strict
	// bundler inside openapi-typescript does not. Each definition declares its
	// referenced types in Dependencies, so stub any that are absent as a
	// permissive empty schema, keeping the document self-contained.
	var stubbed int
	for _, def := range defs {
		for _, dep := range def.Dependencies {
			depName, _ := namer.GetDefinitionName(dep)
			if _, ok := schemas[depName]; !ok {
				schemas[depName] = spec.Schema{}
				stubbed++
			}
		}
	}

	doc := map[string]any{
		"openapi":    "3.0.0",
		"info":       map[string]any{"title": *title, "version": *version},
		"paths":      map[string]any{},
		"components": map[string]any{"schemas": schemas},
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "openapi-dump: marshal:", err)
		os.Exit(1)
	}
	b = append(b, '\n')

	if *out == "" {
		if _, err := os.Stdout.Write(b); err != nil {
			fmt.Fprintln(os.Stderr, "openapi-dump: write:", err)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "openapi-dump: write:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "openapi-dump: wrote %d schemas (%d stubbed) to %s\n", len(schemas), stubbed, *out)
}
