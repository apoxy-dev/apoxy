// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"errors"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	oauth2v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes/duration"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
)

const (
	oauth2Filter = "envoy.filters.http.oauth2"
)

func init() {
	registerHTTPFilter(&oidc{})
}

type oidc struct {
}

var _ httpFilter = &oidc{}

// patchHCM builds and appends the oauth2 Filters to the HTTP Connection Manager
// if applicable, and it does not already exist.
// Note: this method creates an oauth2 filter for each route that contains an OIDC config.
// the filter is disabled by default. It is enabled on the route level.
func (*oidc) patchHCM(mgr *hcmv3.HttpConnectionManager, irListener *ir.HTTPListener) error {
	var errs error

	if mgr == nil {
		return errors.New("hcm is nil")
	}

	if irListener == nil {
		return errors.New("ir listener is nil")
	}

	for _, route := range irListener.Routes {
		if !routeContainsOIDC(route) {
			continue
		}

		filter, err := buildHCMOAuth2Filter(route)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		mgr.HttpFilters = append(mgr.HttpFilters, filter)
	}

	return errs
}

// buildHCMOAuth2Filter returns an OAuth2 HTTP filter from the provided IR HTTPRoute.
func buildHCMOAuth2Filter(route *ir.HTTPRoute) (*hcmv3.HttpFilter, error) {
	oauth2Proto, err := oauth2Config(route)
	if err != nil {
		return nil, err
	}

	if err := oauth2Proto.ValidateAll(); err != nil {
		return nil, err
	}

	OAuth2Any, err := anypb.New(oauth2Proto)
	if err != nil {
		return nil, err
	}

	return &hcmv3.HttpFilter{
		Name:     oauth2FilterName(route),
		Disabled: true,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: OAuth2Any,
		},
	}, nil
}

func oauth2FilterName(route *ir.HTTPRoute) string {
	return fmt.Sprintf("%s_%s", oauth2Filter, route.Name)
}

func oauth2Config(route *ir.HTTPRoute) (*oauth2v3.OAuth2, error) {
	cluster, err := url2Cluster(route.OIDC.Provider.TokenEndpoint)
	if err != nil {
		return nil, err
	}
	if cluster.endpointType == EndpointTypeStatic {
		return nil, fmt.Errorf(
			"static IP cluster is not allowed: %s",
			route.OIDC.Provider.TokenEndpoint)
	}

	oauth2 := &oauth2v3.OAuth2{
		Config: &oauth2v3.OAuth2Config{
			TokenEndpoint: &corev3.HttpUri{
				Uri: route.OIDC.Provider.TokenEndpoint,
				HttpUpstreamType: &corev3.HttpUri_Cluster{
					Cluster: cluster.name,
				},
				Timeout: &duration.Duration{
					Seconds: defaultExtServiceRequestTimeout,
				},
			},
			AuthorizationEndpoint: route.OIDC.Provider.AuthorizationEndpoint,
			RedirectUri:           route.OIDC.RedirectURL,
			RedirectPathMatcher: &matcherv3.PathMatcher{
				Rule: &matcherv3.PathMatcher_Path{
					Path: &matcherv3.StringMatcher{
						MatchPattern: &matcherv3.StringMatcher_Exact{
							Exact: route.OIDC.RedirectPath,
						},
					},
				},
			},
			SignoutPath: &matcherv3.PathMatcher{
				Rule: &matcherv3.PathMatcher_Path{
					Path: &matcherv3.StringMatcher{
						MatchPattern: &matcherv3.StringMatcher_Exact{
							Exact: route.OIDC.LogoutPath,
						},
					},
				},
			},
			ForwardBearerToken: true,
			Credentials: &oauth2v3.OAuth2Credentials{
				ClientId: route.OIDC.ClientID,
				TokenSecret: &tlsv3.SdsSecretConfig{
					Name:      oauth2ClientSecretName(route),
					SdsConfig: makeConfigSource(),
				},
				TokenFormation: &oauth2v3.OAuth2Credentials_HmacSecret{
					HmacSecret: &tlsv3.SdsSecretConfig{
						Name:      oauth2HMACSecretName(route),
						SdsConfig: makeConfigSource(),
					},
				},
				CookieNames: &oauth2v3.OAuth2Credentials_CookieNames{
					BearerToken:  fmt.Sprintf("BearerToken-%s", route.OIDC.CookieSuffix),
					OauthHmac:    fmt.Sprintf("OauthHMAC-%s", route.OIDC.CookieSuffix),
					OauthExpires: fmt.Sprintf("OauthExpires-%s", route.OIDC.CookieSuffix),
					IdToken:      fmt.Sprintf("IdToken-%s", route.OIDC.CookieSuffix),
					RefreshToken: fmt.Sprintf("RefreshToken-%s", route.OIDC.CookieSuffix),
				},
			},
			// every OIDC provider supports basic auth
			AuthType:   oauth2v3.OAuth2Config_BASIC_AUTH,
			AuthScopes: route.OIDC.Scopes,
		},
	}
	return oauth2, nil
}

// routeContainsOIDC returns true if OIDC exists for the provided route.
func routeContainsOIDC(irRoute *ir.HTTPRoute) bool {
	if irRoute == nil {
		return false
	}

	if irRoute != nil &&
		irRoute.OIDC != nil {
		return true
	}

	return false
}

func (*oidc) patchResources(tCtx *types.ResourceVersionTable,
	routes []*ir.HTTPRoute) error {
	if err := createOAuth2TokenEndpointClusters(tCtx, routes); err != nil {
		return err
	}
	if err := createOAuth2Secrets(tCtx, routes); err != nil {
		return err
	}
	return nil
}

// createOAuth2TokenEndpointClusters creates token endpoint clusters from the
// provided routes, if needed.
func createOAuth2TokenEndpointClusters(tCtx *types.ResourceVersionTable,
	routes []*ir.HTTPRoute) error {
	if tCtx == nil || tCtx.XdsResources == nil {
		return errors.New("xds resource table is nil")
	}

	var errs error
	for _, route := range routes {
		if !routeContainsOIDC(route) {
			continue
		}

		var (
			cluster *urlCluster
			ds      *ir.DestinationSetting
			tSocket *corev3.TransportSocket
			err     error
		)

		cluster, err = url2Cluster(route.OIDC.Provider.TokenEndpoint)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		// EG does not support static IP clusters for token endpoint clusters.
		// This validation could be removed since it's already validated in the
		// Gateway API translator.
		if cluster.endpointType == EndpointTypeStatic {
			errs = errors.Join(errs, fmt.Errorf(
				"static IP cluster is not allowed: %s",
				route.OIDC.Provider.TokenEndpoint))
			continue
		}

		ds = &ir.DestinationSetting{
			Weight: ptr.To[uint32](1),
			Endpoints: []*ir.DestinationEndpoint{ir.NewDestEndpoint(
				cluster.hostname,
				cluster.port),
			},
		}

		clusterArgs := &xdsClusterArgs{
			name:         cluster.name,
			settings:     []*ir.DestinationSetting{ds},
			tSocket:      tSocket,
			endpointType: cluster.endpointType,
		}
		if cluster.tls {
			tSocket, err = buildXdsUpstreamTLSSocket(cluster.hostname)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			clusterArgs.tSocket = tSocket
		}

		if err = addXdsCluster(tCtx, clusterArgs); err != nil && !errors.Is(err, ErrXdsClusterExists) {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

// createOAuth2Secrets creates OAuth2 client and HMAC secrets from the provided
// routes, if needed.
func createOAuth2Secrets(tCtx *types.ResourceVersionTable, routes []*ir.HTTPRoute) error {
	var errs error

	for _, route := range routes {
		if !routeContainsOIDC(route) {
			continue
		}

		// a separate secret is created for each route, even they share the same
		// oauth2 client ID and secret.
		clientSecret := buildOAuth2ClientSecret(route)
		if err := addXdsSecret(tCtx, clientSecret); err != nil {
			errs = errors.Join(errs, err)
		}

		if err := addXdsSecret(tCtx, buildOAuth2HMACSecret(route)); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func buildOAuth2ClientSecret(route *ir.HTTPRoute) *tlsv3.Secret {
	clientSecret := &tlsv3.Secret{
		Name: oauth2ClientSecretName(route),
		Type: &tlsv3.Secret_GenericSecret{
			GenericSecret: &tlsv3.GenericSecret{
				Secret: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{
						InlineBytes: route.OIDC.ClientSecret,
					},
				},
			},
		},
	}

	return clientSecret
}

func buildOAuth2HMACSecret(route *ir.HTTPRoute) *tlsv3.Secret {
	hmacSecret := &tlsv3.Secret{
		Name: oauth2HMACSecretName(route),
		Type: &tlsv3.Secret_GenericSecret{
			GenericSecret: &tlsv3.GenericSecret{
				Secret: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{
						InlineBytes: route.OIDC.HMACSecret,
					},
				},
			},
		},
	}

	return hmacSecret
}

func oauth2ClientSecretName(route *ir.HTTPRoute) string {
	return fmt.Sprintf("%s/oauth2/client_secret", route.Name)
}

func oauth2HMACSecretName(route *ir.HTTPRoute) string {
	return fmt.Sprintf("%s/oauth2/hmac_secret", route.Name)
}

// patchRoute patches the provided route with the oauth2 config if applicable.
// Note: this method enables the corresponding oauth2 filter for the provided route.
func (*oidc) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if route == nil {
		return errors.New("xds route is nil")
	}
	if irRoute == nil {
		return errors.New("ir route is nil")
	}
	if irRoute.OIDC == nil {
		return nil
	}

	if err := enableFilterOnRoute(route, oauth2FilterName(irRoute)); err != nil {
		return err
	}
	return nil
}
