// Package start provides server startup logic for the API server.
// This is inspired by tilt-apiserver's pkg/server/start package.
package start

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
)

// CertKey contains configuration for TLS certificate files.
type CertKey struct {
	// CertFile is a file containing a PEM-encoded certificate.
	CertFile string
	// KeyFile is a file containing a PEM-encoded private key.
	KeyFile string
}

// GeneratableKeyCert contains configuration for certificate generation.
type GeneratableKeyCert struct {
	// CertDirectory specifies a directory to write generated certificates to if CertFile/KeyFile aren't provided.
	CertDirectory string
	// PairName is the name of the certificate pair (e.g., "apiserver").
	PairName string
	// CertKey holds explicit certificate file paths.
	CertKey CertKey
	// GeneratedCert is an in-memory certificate provider.
	GeneratedCert dynamiccertificates.CertKeyContentProvider
}

// SecureServingOptions contains configuration for serving the API server over TLS.
type SecureServingOptions struct {
	// BindAddress is the IP address to bind to.
	BindAddress net.IP
	// BindPort is the port to bind to.
	BindPort int
	// BindNetwork is the network type (e.g., "tcp", "tcp4", "tcp6").
	BindNetwork string
	// Required specifies whether secure serving is required.
	Required bool
	// ServerCert contains certificate configuration.
	ServerCert GeneratableKeyCert
	// Listener is an optional pre-created listener to use instead of creating one.
	Listener net.Listener
}

// NewSecureServingOptions returns a SecureServingOptions with default values.
func NewSecureServingOptions() *SecureServingOptions {
	return &SecureServingOptions{
		BindAddress: net.ParseIP("0.0.0.0"),
		BindPort:    8443,
		BindNetwork: "tcp",
		ServerCert: GeneratableKeyCert{
			PairName: "apiserver",
		},
	}
}

// Validate checks if the options are valid.
func (s *SecureServingOptions) Validate() []error {
	if s == nil {
		return nil
	}

	errors := []error{}

	if s.BindPort < 0 || s.BindPort > 65535 {
		errors = append(errors, fmt.Errorf("--secure-port must be between 0 and 65535, inclusive. %d is not allowed", s.BindPort))
	}

	return errors
}

// MaybeDefaultWithSelfSignedCerts generates self-signed certificates if no cert files are provided.
func (s *SecureServingOptions) MaybeDefaultWithSelfSignedCerts(publicAddress string, alternateDNS []string, alternateIPs []net.IP) error {
	if s.ServerCert.CertKey.CertFile != "" && s.ServerCert.CertKey.KeyFile != "" {
		return nil
	}
	if s.ServerCert.GeneratedCert != nil {
		return nil
	}

	// Generate self-signed certificate
	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert(publicAddress)
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}

	certDir := s.ServerCert.CertDirectory
	if certDir == "" {
		// Use temp directory if no cert directory specified
		certDir, err = os.MkdirTemp("", "apiserver-certs-")
		if err != nil {
			return fmt.Errorf("failed to create temp cert directory: %w", err)
		}
	}

	// Save to files
	if err := cryptoutils.SaveCertificatePEM(caCert, certDir, "ca", true); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}
	if err := cryptoutils.SaveCertificatePEM(serverCert, certDir, s.ServerCert.PairName, false); err != nil {
		return fmt.Errorf("failed to save server certificate: %w", err)
	}
	s.ServerCert.CertKey.CertFile = filepath.Join(certDir, s.ServerCert.PairName+".crt")
	s.ServerCert.CertKey.KeyFile = filepath.Join(certDir, s.ServerCert.PairName+".key")

	return nil
}

// ApplyTo applies the secure serving options to the server config.
func (s *SecureServingOptions) ApplyTo(c **server.SecureServingInfo) error {
	if s == nil {
		*c = nil
		return nil
	}

	var listener net.Listener
	var err error

	if s.Listener != nil {
		listener = s.Listener
	} else {
		addr := net.JoinHostPort(s.BindAddress.String(), strconv.Itoa(s.BindPort))
		listener, err = net.Listen(s.BindNetwork, addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
	}

	*c = &server.SecureServingInfo{
		Listener: listener,
	}

	if s.ServerCert.CertKey.CertFile != "" && s.ServerCert.CertKey.KeyFile != "" {
		provider, err := dynamiccertificates.NewDynamicServingContentFromFiles(
			"serving-cert",
			s.ServerCert.CertKey.CertFile,
			s.ServerCert.CertKey.KeyFile,
		)
		if err != nil {
			return fmt.Errorf("failed to load serving cert: %w", err)
		}
		(*c).Cert = provider
	} else if s.ServerCert.GeneratedCert != nil {
		(*c).Cert = s.ServerCert.GeneratedCert
	}

	return nil
}
