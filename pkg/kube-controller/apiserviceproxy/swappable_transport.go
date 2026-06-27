package apiserviceproxy

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/cert/reload"
)

// swappableTransport delegates to an inner *http.Transport that can be
// replaced atomically. New requests after a swap dial with the new TLS
// config; in-flight requests on already-established TCP connections finish
// with the old config. The atomic load on every RoundTrip is negligible.
type swappableTransport struct {
	inner atomic.Pointer[http.Transport]
}

func newSwappableTransport(t *http.Transport) *swappableTransport {
	s := &swappableTransport{}
	s.inner.Store(t)
	return s
}

func (s *swappableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.inner.Load().RoundTrip(req)
}

// Store atomically swaps the inner transport and returns the previous
// one for connection cleanup.
func (s *swappableTransport) Store(t *http.Transport) *http.Transport {
	return s.inner.Swap(t)
}

// buildTransport constructs a fresh *http.Transport for the given cert
// bundle. Extracted from cloud.go so both the bootstrap path and the
// reload path produce identical transport configs.
func buildTransport(b *reload.Bundle, localMode bool) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{b.Cert},
			RootCAs:            b.RootCAs,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: localMode,
		},
	}
}
