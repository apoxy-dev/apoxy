package resource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/yaml"
)

// ApplyOptions controls server-side apply behavior.
type ApplyOptions struct {
	// FieldManager identifies the actor for managed-fields tracking.
	// Defaults to "apoxy-cli" when empty.
	FieldManager string
	// Force resolves field-ownership conflicts in this caller's favor.
	Force bool
}

// ReadInputs collects YAML/JSON contents from a list of paths. Each path may
// be a file, a directory (walked for *.yaml / *.yml / *.json; descends into
// subdirs only when recursive is true), or "-" to read from stdin. Returns
// one []byte per source file — callers should pass each through
// SplitYAMLDocuments to handle multi-doc streams.
func ReadInputs(paths []string, recursive bool) ([][]byte, error) {
	var all [][]byte
	for _, p := range paths {
		docs, err := readInput(p, recursive)
		if err != nil {
			return nil, err
		}
		all = append(all, docs...)
	}
	return all, nil
}

func readInput(path string, recursive bool) ([][]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return [][]byte{data}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		return [][]byte{data}, nil
	}
	var out [][]byte
	walkErr := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if p != path && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading %s: %w", p, err)
		}
		out = append(out, data)
		return nil
	})
	return out, walkErr
}

// SplitYAMLDocuments splits a multi-doc YAML stream on "\n---" boundaries.
// Empty documents are dropped.
func SplitYAMLDocuments(data []byte) [][]byte {
	var out [][]byte
	for _, doc := range bytes.Split(data, []byte("\n---")) {
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		out = append(out, doc)
	}
	return out
}

// Apply server-side-applies a single resource document (YAML or JSON) using
// the supplied dynamic client and REST mapper. Returns the applied object's
// name and kind for status reporting. data must be a single document — call
// SplitYAMLDocuments first if you have a multi-doc stream.
func Apply(
	ctx context.Context,
	dynClient dynamic.Interface,
	mapper *restmapper.DeferredDiscoveryRESTMapper,
	data []byte,
	opts ApplyOptions,
) (name, kind string, err error) {
	if opts.FieldManager == "" {
		opts.FieldManager = "apoxy-cli"
	}

	obj, err := decodeUnstructured(data)
	if err != nil {
		return "", "", err
	}
	gvk := obj.GroupVersionKind()
	kind = gvk.Kind

	name = obj.GetName()
	if name == "" {
		if fn, ok := LookupDefaultName(gvk); ok {
			derived, err := fn(data)
			if err != nil {
				return "", kind, err
			}
			obj.SetName(derived)
			name = derived
		}
	}
	if name == "" {
		return "", kind, errors.New("resource name is required")
	}

	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return name, kind, fmt.Errorf("REST mapping for %s: %w", gvk, err)
	}
	patch, err := obj.MarshalJSON()
	if err != nil {
		return name, kind, fmt.Errorf("encoding %s %q: %w", kind, name, err)
	}
	_, err = dynClient.Resource(mapping.Resource).
		Namespace(obj.GetNamespace()).
		Patch(ctx, name, types.ApplyPatchType, patch, metav1.PatchOptions{
			FieldManager: opts.FieldManager,
			Force:        &opts.Force,
		})
	if err != nil {
		return name, kind, fmt.Errorf("applying %s %q: %w", kind, name, err)
	}
	return name, kind, nil
}

// decodeUnstructured parses a single YAML/JSON document. We decode via
// sigs.k8s.io/yaml (which routes through the JSON path) so this works
// without registering any scheme — important for callers that bring their
// own CRDs (e.g. clrk).
func decodeUnstructured(data []byte) (*unstructured.Unstructured, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding YAML: %w", err)
	}
	if raw == nil {
		return nil, errors.New("empty document")
	}
	u := &unstructured.Unstructured{Object: raw}
	if u.GetKind() == "" || u.GetAPIVersion() == "" {
		return nil, errors.New("apiVersion and kind are required")
	}
	return u, nil
}
