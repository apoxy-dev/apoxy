package translator

import (
	"errors"
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	brotliv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/brotli/compressor/v3"
	gzipv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/compressor/v3"
	zstdv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/zstd/compressor/v3"
	compressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/gateway/xds/types"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	compressorFilter        = "envoy.filters.http.compressor"
	defaultCompressorPrefix = "default"
)

func init() {
	registerHTTPFilter(&compressorHTTPFilter{})
}

type compressorHTTPFilter struct{}

var _ httpFilter = &compressorHTTPFilter{}

// defaultCompressorFilterName returns the HCM filter name for a default
// compressor filter for the given algorithm.
func defaultCompressorFilterName(algo extensionsv1alpha2.CompressorAlgorithm) string {
	return perRouteFilterName(compressorFilter, fmt.Sprintf("%s/%s", defaultCompressorPrefix, algo))
}

// compressorAlgoFilterName returns a unique HCM filter name for a specific
// algorithm on a specific HTTPRouteFilter object.
func compressorAlgoFilterName(un *unstructured.Unstructured, algo extensionsv1alpha2.CompressorAlgorithm) string {
	return perRouteFilterName(compressorFilter, fmt.Sprintf("%s/%s", un.GetName(), algo))
}

// resolveAlgorithms returns the effective algorithm list, defaulting to all
// three when the spec list is empty.
func resolveAlgorithms(spec *extensionsv1alpha2.CompressorSpec) []extensionsv1alpha2.CompressorAlgorithm {
	if len(spec.Algorithms) > 0 {
		return spec.Algorithms
	}
	return extensionsv1alpha2.DefaultCompressorAlgorithms
}

// resolveMinContentLength returns the effective minimum content length,
// defaulting to DefaultCompressorMinContentLength.
func resolveMinContentLength(spec *extensionsv1alpha2.CompressorSpec) uint32 {
	if spec.MinContentLength != nil {
		return *spec.MinContentLength
	}
	return extensionsv1alpha2.DefaultCompressorMinContentLength
}

// hasCustomCompressorSettings returns true if the compressor spec has any
// non-default settings that require separate filter instances.
func hasCustomCompressorSettings(spec *extensionsv1alpha2.CompressorSpec) bool {
	return len(spec.Algorithms) > 0 || spec.MinContentLength != nil || len(spec.ContentType) > 0
}

// patchHCM adds compressor filters to the HCM. Default filters (all algos,
// 128-byte min) are always added. Custom per-route filters are added for
// routes with non-default HTTPRouteFilter settings. All filters are added
// disabled and selectively enabled per-route in patchRoute.
func (*compressorHTTPFilter) patchHCM(mgr *hcmv3.HttpConnectionManager, irListener *ir.HTTPListener) error {
	if mgr == nil {
		return errors.New("hcm is nil")
	}
	if irListener == nil {
		return errors.New("ir listener is nil")
	}

	// Always add default compressor filters (disabled, enabled per-route).
	for _, algo := range extensionsv1alpha2.DefaultCompressorAlgorithms {
		name := defaultCompressorFilterName(algo)
		if hcmContainsFilter(mgr, name) {
			continue
		}
		compressor, err := buildCompressorProto(algo, extensionsv1alpha2.DefaultCompressorMinContentLength, nil)
		if err != nil {
			return fmt.Errorf("failed to build default compressor proto for %s: %w", algo, err)
		}
		compressorAny, err := anypb.New(compressor)
		if err != nil {
			return fmt.Errorf("failed to marshal default compressor config: %w", err)
		}
		log.Infof("Adding default compressor filter %s", name)
		mgr.HttpFilters = append(mgr.HttpFilters, &hcmv3.HttpFilter{
			Name:     name,
			Disabled: true,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{
				TypedConfig: compressorAny,
			},
		})
	}

	// Add custom per-route compressor filters for routes with non-default settings.
	var errs error
	for _, route := range irListener.Routes {
		for _, er := range route.ExtensionRefs {
			if er.Object.GroupVersionKind().Group != extensionsv1alpha2.GroupVersion.Group ||
				er.Object.GroupVersionKind().Kind != "HTTPRouteFilter" {
				continue
			}

			filters, err := buildCustomCompressorFilters(er.Object)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}

			for _, f := range filters {
				if hcmContainsFilter(mgr, f.Name) {
					continue
				}
				log.Infof("Adding custom compressor filter %s", f.Name)
				mgr.HttpFilters = append(mgr.HttpFilters, f)
			}
		}
	}

	return errs
}

// buildCustomCompressorFilters returns disabled HCM filters for routes that
// need custom compressor settings. Returns nil if the spec is disabled, absent,
// or uses only default settings.
func buildCustomCompressorFilters(un *unstructured.Unstructured) ([]*hcmv3.HttpFilter, error) {
	hrf := &extensionsv1alpha2.HTTPRouteFilter{}
	if err := conv.FromUnstructured(un.UnstructuredContent(), hrf); err != nil {
		return nil, fmt.Errorf("failed to convert unstructured to HTTPRouteFilter: %w", err)
	}

	if hrf.Spec.Compressor == nil {
		return nil, nil
	}

	// Disabled or default-only settings don't need custom HCM filters.
	if (hrf.Spec.Compressor.Disabled != nil && *hrf.Spec.Compressor.Disabled) ||
		!hasCustomCompressorSettings(hrf.Spec.Compressor) {
		return nil, nil
	}

	algos := resolveAlgorithms(hrf.Spec.Compressor)
	minLen := resolveMinContentLength(hrf.Spec.Compressor)

	var filters []*hcmv3.HttpFilter
	for _, algo := range algos {
		compressor, err := buildCompressorProto(algo, minLen, hrf.Spec.Compressor.ContentType)
		if err != nil {
			return nil, fmt.Errorf("failed to build compressor proto for %s/%s: %w", hrf.Name, algo, err)
		}

		compressorAny, err := anypb.New(compressor)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal compressor config: %w", err)
		}

		filters = append(filters, &hcmv3.HttpFilter{
			Name:     compressorAlgoFilterName(un, algo),
			Disabled: true,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{
				TypedConfig: compressorAny,
			},
		})
	}

	return filters, nil
}

func buildCompressorProto(algo extensionsv1alpha2.CompressorAlgorithm, minContentLength uint32, contentType []string) (*compressorv3.Compressor, error) {
	// Build algorithm-specific library config.
	var libraryMsg proto.Message
	var libraryName string
	switch algo {
	case extensionsv1alpha2.CompressorAlgorithmGzip:
		libraryMsg = &gzipv3.Gzip{}
		libraryName = "gzip"
	case extensionsv1alpha2.CompressorAlgorithmBrotli:
		libraryMsg = &brotliv3.Brotli{}
		libraryName = "brotli"
	case extensionsv1alpha2.CompressorAlgorithmZstd:
		libraryMsg = &zstdv3.Zstd{}
		libraryName = "zstd"
	default:
		return nil, fmt.Errorf("unsupported compressor algorithm: %s", algo)
	}

	libraryAny, err := anypb.New(libraryMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal compressor library config: %w", err)
	}

	commonConfig := &compressorv3.Compressor_CommonDirectionConfig{
		MinContentLength: wrapperspb.UInt32(minContentLength),
	}
	if len(contentType) > 0 {
		commonConfig.ContentType = contentType
	}

	return &compressorv3.Compressor{
		CompressorLibrary: &corev3.TypedExtensionConfig{
			Name:        libraryName,
			TypedConfig: libraryAny,
		},
		ResponseDirectionConfig: &compressorv3.Compressor_ResponseDirectionConfig{
			CommonConfig: commonConfig,
		},
	}, nil
}

// patchRoute enables compressor filters per-route. By default, compression is
// enabled on all routes using the default filters. Routes with custom
// HTTPRouteFilter settings get custom filters instead. Routes with a disabled
// HTTPRouteFilter get no compression.
func (*compressorHTTPFilter) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if route == nil {
		return errors.New("xds route is nil")
	}
	if irRoute == nil {
		return errors.New("ir route is nil")
	}

	// Check whether this route has a compressor HTTPRouteFilter override.
	var compressorRef *ir.UnstructuredRef
	var compressorSpec *extensionsv1alpha2.CompressorSpec

	for _, er := range irRoute.ExtensionRefs {
		if er.Object.GroupVersionKind().Group != extensionsv1alpha2.GroupVersion.Group ||
			er.Object.GroupVersionKind().Kind != "HTTPRouteFilter" {
			continue
		}

		hrf := &extensionsv1alpha2.HTTPRouteFilter{}
		if err := conv.FromUnstructured(er.Object.UnstructuredContent(), hrf); err != nil {
			return fmt.Errorf("failed to convert unstructured to HTTPRouteFilter: %w", err)
		}

		if hrf.Spec.Compressor == nil {
			continue
		}

		compressorRef = er
		compressorSpec = hrf.Spec.Compressor
		break
	}

	switch {
	case compressorSpec != nil && compressorSpec.Disabled != nil && *compressorSpec.Disabled:
		// Disabled: don't enable any compressor filters on this route.
		return nil

	case compressorSpec != nil && hasCustomCompressorSettings(compressorSpec):
		// Custom settings: enable custom filters instead of defaults.
		for _, algo := range resolveAlgorithms(compressorSpec) {
			if err := enableFilterOnRoute(route, compressorAlgoFilterName(compressorRef.Object, algo)); err != nil {
				return err
			}
		}
		return nil

	default:
		// No override or empty spec: enable default compression.
		for _, algo := range extensionsv1alpha2.DefaultCompressorAlgorithms {
			if err := enableFilterOnRoute(route, defaultCompressorFilterName(algo)); err != nil {
				return err
			}
		}
		return nil
	}
}

func (*compressorHTTPFilter) patchResources(
	tCtx *types.ResourceVersionTable,
	routes []*ir.HTTPRoute,
) error {
	return nil
}
