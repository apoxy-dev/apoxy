package cmd

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"

	sigyaml "sigs.k8s.io/yaml"

	"github.com/apoxy-dev/apoxy/pkg/cmd/utils"
)

// randomName returns a random "adjective-noun" pair drawn from the given
// lists. Some commands use their own vocabularies instead of Docker names.
func randomName(adjs, nouns []string) string {
	return adjs[rand.IntN(len(adjs))] + "-" + nouns[rand.IntN(len(nouns))]
}

// generateServiceName returns a random docker-style adjective-noun pair,
// e.g. "elegant-turing".
func generateServiceName() string {
	return utils.DockerName()
}

// bootstrapServiceManifest renders the minimal Service manifest deploy
// generates when a project has no service.yaml. Everything else (backend
// mode, protocol, revision history) is filled by server-side defaulting, so
// the file stays an honest statement of what the user actually chose.
// Marshaled rather than templated so values needing YAML quoting come out
// well-formed.
func bootstrapServiceManifest(name, repo string) ([]byte, error) {
	obj := map[string]any{
		"apiVersion": "compute.apoxy.dev/v1alpha1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": name},
	}
	if repo != "" {
		obj["spec"] = map[string]any{
			"source": map[string]any{
				"oci": map[string]any{"repo": repo},
			},
		}
	}
	return sigyaml.Marshal(obj)
}

// writeBootstrapManifest writes the generated manifest into the project dir,
// refusing to clobber an existing file (the caller only bootstraps when the
// manifest is missing, so hitting one here means a race or a logic bug).
func writeBootstrapManifest(path, name, repo string) error {
	doc, err := bootstrapServiceManifest(name, repo)
	if err != nil {
		return fmt.Errorf("rendering %s: %w", filepath.Base(path), err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	if _, err := f.Write(doc); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	return nil
}
