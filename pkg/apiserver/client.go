package apiserver

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"github.com/apoxy-dev/apoxy/build"
)

// ClientOption is a set of options for the client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	host              string
	tlsConfig         rest.TLSClientConfig
	bearerToken       string
	transportWrapFunc transport.WrapperFunc
}

// WithClientHost sets the host for the client.
// The default host is "localhost:8443".
func WithClientHost(host string) ClientOption {
	return func(o *clientOptions) {
		o.host = host
	}
}

// WithClientTLSConfig sets the TLS configuration for the client.
// If not set, the client will use an insecure configuration.
func WithClientTLSConfig(tlsConfig rest.TLSClientConfig) ClientOption {
	return func(o *clientOptions) {
		o.tlsConfig = tlsConfig
	}
}

// WithBearerToken sets the token for the client.
func WithBearerToken(token string) ClientOption {
	return func(o *clientOptions) {
		o.bearerToken = token
	}
}

// WithTransportWrapper sets the transport wrapper for the client.
func WithTransportWrapper(fn transport.WrapperFunc) ClientOption {
	return func(o *clientOptions) {
		o.transportWrapFunc = fn
	}
}

func defaultClientOptions() *clientOptions {
	return &clientOptions{
		host: "localhost:8443",
		tlsConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}
}

// NewClientConfig returns a new local client configuration.
func NewClientConfig(opts ...ClientOption) *rest.Config {
	sOpts := defaultClientOptions()
	for _, opt := range opts {
		opt(sOpts)
	}
	return &rest.Config{
		QPS:             -1,
		Host:            fmt.Sprintf("https://%s", sOpts.host),
		TLSClientConfig: sOpts.tlsConfig,
		BearerToken:     sOpts.bearerToken,
		WrapTransport:   sOpts.transportWrapFunc,
		UserAgent:       build.APIServerUserAgent(),
	}
}
