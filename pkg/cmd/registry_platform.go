package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/config"
)

// platformRegistry is the resolved platform bundle registry for the current
// project: where `apoxy deploy` pushes when the Service names no repo, and
// which host authenticates with the project API key instead of the docker
// credential store.
type platformRegistry struct {
	// Host is the registry host, e.g. "registry.apoxy.dev".
	Host      string
	ProjectID uuid.UUID
	APIKey    string
}

// DefaultRepo returns the platform repo for a service:
// <host>/<project-id>/<service>. The project UUID prefix is the tenancy
// boundary the platform enforces.
func (r *platformRegistry) DefaultRepo(service string) string {
	return fmt.Sprintf("%s/%s/%s", r.Host, r.ProjectID, service)
}

// tlsClientConfig returns the TLS override for pushes to the platform
// registry, or nil for the default transport. The dev registry
// (registry.apoxy.localhost, fronted by the Tilt cluster's Contour) serves a
// selfsigned certificate the host has no reason to trust; every hosted
// registry carries a publicly-trusted cert and gets full verification.
func (r *platformRegistry) tlsClientConfig() *tls.Config {
	if strings.HasSuffix(r.Host, ".apoxy.localhost") {
		return &tls.Config{InsecureSkipVerify: true}
	}
	return nil
}

// registryHostForAPI maps the well-known API hosts to their platform
// registry. Anything else (on-prem, kubeconfig-backed projects) has no
// implicit platform registry.
func registryHostForAPI(apiHost string) string {
	switch apiHost {
	case "api.apoxy.dev":
		return "registry.apoxy.dev"
	case "api-staging.apoxy.dev":
		return "registry.staging.apoxy.dev"
	case "api.apoxy.localhost":
		return "registry.apoxy.localhost"
	}
	return ""
}

// projectAPIHost returns the API hostname a config project talks to:
// APIBaseHost (the Host-header override) when set, else the hostname of
// APIBaseURL, else the default hosted API — matching how the rest client
// resolves the same fields. Ports are stripped: the registry mapping is by
// name.
func projectAPIHost(p configv1alpha1.Project) string {
	if p.APIBaseHost != "" {
		if host, _, err := net.SplitHostPort(p.APIBaseHost); err == nil {
			return host
		}
		return p.APIBaseHost
	}
	if p.APIBaseURL != "" {
		u, err := url.Parse(p.APIBaseURL)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	return "api.apoxy.dev"
}

// currentPlatformRegistry resolves the platform registry for the config's
// current project. ok is false when there is none: no config, no current
// project, no API key, or a project pointed at an environment without a
// platform registry.
func currentPlatformRegistry() (*platformRegistry, bool) {
	cfg, err := config.Load()
	if err != nil || cfg.CurrentProject == uuid.Nil {
		return nil, false
	}
	idx := slices.IndexFunc(cfg.Projects, func(p configv1alpha1.Project) bool {
		return p.ID == cfg.CurrentProject
	})
	if idx == -1 {
		return nil, false
	}
	p := cfg.Projects[idx]
	host := p.Registry
	if host == "" {
		host = registryHostForAPI(projectAPIHost(p))
	}
	if host == "" || p.APIKey == "" {
		return nil, false
	}
	return &platformRegistry{Host: host, ProjectID: p.ID, APIKey: p.APIKey}, true
}
