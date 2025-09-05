package rest

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/rest"

	"github.com/apoxy-dev/apoxy/build"
)

type A3YClient struct {
}

func addSubdomain(baseURL, subdomain string) (*url.URL, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(parsedURL.Hostname(), ".")
	parts = append([]string{subdomain}, parts...)
	parsedURL.Host = strings.Join(parts, ".")
	return parsedURL, nil
}

type headerTransport struct {
	roundTripper http.RoundTripper
	apiKey       string
	projectID    uuid.UUID
	host         string
}

var _ utilnet.RoundTripperWrapper = &headerTransport{}

// RoundTrip implements the http.RoundTripper interface.
func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-Apoxy-API-Key", t.apiKey)
	req.Header.Set("X-Apoxy-Project-Id", t.projectID.String())
	req.Header.Set("User-Agent", build.UserAgent())
	if t.host != "" {
		req.Host = t.host
	}
	return t.roundTripper.RoundTrip(req)
}

// WrappedRoundTripper implements the utilnet.RoundTripperWrapper interface.
func (t *headerTransport) WrappedRoundTripper() http.RoundTripper {
	return t.roundTripper
}

func newA3YRESTConfig(baseURL, baseHost, apiKey string, projectID uuid.UUID) (*rest.Config, error) {
	url, err := addSubdomain(baseURL, projectID.String())
	if err != nil {
		return nil, err
	}
	config := &rest.Config{
		Host:      fmt.Sprintf("https://%s", url.Host),
		UserAgent: build.UserAgent(),
		Timeout:   10 * time.Second,
	}
	if baseHost != "" {
		config.Host = baseURL
		config.TLSClientConfig = rest.TLSClientConfig{
			Insecure:   true,
			ServerName: fmt.Sprintf("%v.%s", projectID, baseHost),
		}
	}
	config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		ht := &headerTransport{
			roundTripper: rt,
			apiKey:       apiKey,
			projectID:    projectID,
		}
		if baseHost != "" {
			ht.host = fmt.Sprintf("%v.%s", projectID, baseHost)
		}
		return ht
	}
	return config, nil
}
