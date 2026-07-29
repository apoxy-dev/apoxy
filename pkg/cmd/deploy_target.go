package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/config"
)

// envLabelForAPI maps the well-known API hosts to a human environment label.
// Anything else (on-prem, kubeconfig-backed, local apiservers) has no label
// and is described by its URL instead.
func envLabelForAPI(apiHost string) string {
	switch apiHost {
	case "api.apoxy.dev":
		return "production"
	case "api-staging.apoxy.dev":
		return "staging"
	case "api.apoxy.localhost":
		return "local dev"
	}
	return ""
}

// fetchProjectName asks the control plane for the project's human-readable
// name (GET /v1/terra/project, authenticated with the project API key).
// Best-effort: any failure returns "" and the caller falls back to the UUID.
func fetchProjectName(ctx context.Context, apiHost, apiKey string) string {
	if apiHost == "" || apiKey == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+apiHost+"/v1/terra/project", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-Apoxy-API-Key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ""
	}
	return out.Name
}

// describeDeployTarget names where a deploy is about to land, preferring what
// a human recognizes: the project name and environment label, falling back to
// the project UUID and API URL. The name comes from the config cache, filled
// on first use from the control plane; the local-mode env fallback mints a
// throwaway project UUID, so the project is only named when the config
// actually selects it.
func describeDeployTarget(ctx context.Context, baseURL string, projectID uuid.UUID) string {
	cfg, err := config.Load()
	if err != nil || cfg.CurrentProject == uuid.Nil || cfg.CurrentProject != projectID {
		return baseURL
	}
	idx := slices.IndexFunc(cfg.Projects, func(p configv1alpha1.Project) bool {
		return p.ID == projectID
	})
	if idx == -1 {
		return baseURL
	}
	p := cfg.Projects[idx]
	apiHost := projectAPIHost(p)
	env := envLabelForAPI(apiHost)
	name := p.Name
	// Only the well-known environments serve the terra endpoint on the API
	// host, so don't dial anything else.
	if name == "" && env != "" {
		if name = fetchProjectName(ctx, apiHost, p.APIKey); name != "" {
			cfg.Projects[idx].Name = name
			// Cache is a nicety; failing to persist it never blocks a deploy.
			_ = config.Store(cfg)
		}
	}
	return formatDeployTarget(name, env, projectID.String(), baseURL)
}

// formatDeployTarget renders the target line from whatever identity is
// available, most recognizable first: name and environment, then whichever
// of the two exists, then the raw UUID + URL.
func formatDeployTarget(name, env, projectID, baseURL string) string {
	switch {
	case name != "" && env != "":
		return fmt.Sprintf("project %q (%s)", name, env)
	case name != "":
		return fmt.Sprintf("project %q at %s", name, baseURL)
	case env != "":
		return fmt.Sprintf("project %s (%s)", projectID, env)
	default:
		return fmt.Sprintf("project %s at %s", projectID, baseURL)
	}
}
