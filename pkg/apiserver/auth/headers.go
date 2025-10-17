// Package auth contains APIServer authentication helpers.
package auth

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/anonymous"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/authentication/request/union"
)

const (
	UserHeaderKey  = "X-Remote-User"
	GroupHeaderKey = "X-Remote-Group"
	ExtraHeaderKey = "X-Remote-Extra-"
)

// NewHeaderAuthenticator returns a new authenticator.Request that authenticates
// requests based on the X-Remote-User, X-Remote-Group, and X-Remote-Extra headers.
func NewHeaderAuthenticator() authenticator.Request {
	rhAuth, _ := headerrequest.New(
		[]string{UserHeaderKey},
		[]string{GroupHeaderKey},
		[]string{ExtraHeaderKey},
		[]string{},
	)
	return union.New(
		rhAuth,
		anonymous.NewAuthenticator(nil /* conditions */),
	)
}

type headerRoundTripper struct {
	roundTripper http.RoundTripper
	userHeader   string
	groupHeaders []string
	extraHeaders []string
}

// NewHeaderRoundTripper returns a new round tripper that adds the given headers to the request.
func NewHeaderRoundTripper(rt http.RoundTripper, userHeader string, groupHeaders, extraHeaders []string) *headerRoundTripper {
	return &headerRoundTripper{
		roundTripper: rt,
		userHeader:   userHeader,
		groupHeaders: groupHeaders,
		extraHeaders: extraHeaders,
	}
}

// RoundTrip implements the http.RoundTripper interface.
func (rt *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(UserHeaderKey, rt.userHeader)
	for _, groupHeader := range rt.groupHeaders {
		req.Header.Add(GroupHeaderKey, groupHeader)
	}
	for _, extraHeader := range rt.extraHeaders {
		req.Header.Add(ExtraHeaderKey, extraHeader)
	}
	return rt.roundTripper.RoundTrip(req)
}

// NewTransportWrapperFunc returns a new transport.WrapperFunc that adds the given headers to the request.
func NewTransportWrapperFunc(userHeader string, groupHeaders, extraHeaders []string) func(rt http.RoundTripper) http.RoundTripper {
	return func(rt http.RoundTripper) http.RoundTripper {
		return NewHeaderRoundTripper(rt, userHeader, groupHeaders, extraHeaders)
	}
}
