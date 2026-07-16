package translator

import (
	"testing"

	golangv3alpha "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/http/golang/v3alpha"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
)

func TestBuildHCMEdgeFuncFilterIgnoresDynamicPluginConfig(t *testing.T) {
	listener := &ir.HTTPListener{
		EdgeFunctionRevisions: []*extensionsv1alpha2.EdgeFunctionRevision{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-filter-abc123"},
				Spec: extensionsv1alpha2.EdgeFunctionRevisionSpec{
					Mode: extensionsv1alpha2.FilterEdgeFunctionMode,
					Code: extensionsv1alpha2.EdgeFunctionCodeSource{
						ObjectMeta:     metav1.ObjectMeta{Name: "test-filter"},
						GoPluginSource: &extensionsv1alpha2.GoPluginSource{PluginConfig: "static: value"},
					},
				},
				Status: extensionsv1alpha2.EdgeFunctionRevisionStatus{Ref: "test-filter-abc123"},
			},
		},
	}

	first := edgeFunctionForTest(t, "first: value", "test-filter")
	second := edgeFunctionForTest(t, "second: value", "test-filter")

	firstFilter, err := buildHCMEdgeFuncFilter(first, listener)
	require.NoError(t, err)
	secondFilter, err := buildHCMEdgeFuncFilter(second, listener)
	require.NoError(t, err)

	assert.True(t, proto.Equal(firstFilter, secondFilter))
	filterConfig := &golangv3alpha.Config{}
	require.NoError(t, firstFilter.GetTypedConfig().UnmarshalTo(filterConfig))
	assert.Equal(t, golangv3alpha.Config_MERGE_VIRTUALHOST_ROUTER_FILTER, filterConfig.GetMergePolicy())
}

func TestEdgeFuncPatchRouteWithDynamicPluginConfig(t *testing.T) {
	tests := []struct {
		name           string
		pluginName     string
		liveRevision   string
		wantPluginName string
	}{
		{
			name:           "explicit plugin name",
			pluginName:     "test-filter",
			liveRevision:   "test-filter-abc123",
			wantPluginName: "test-filter",
		},
		{
			name:           "live revision fallback",
			liveRevision:   "test-filter-abc123",
			wantPluginName: "test-filter-abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fun := edgeFunctionForTest(t, "percentage: 25\nchannels:\n  stable: cluster-a", tt.pluginName)
			fun.Object["status"] = map[string]any{"liveRevision": tt.liveRevision}
			route := &routev3.Route{}
			irRoute := &ir.HTTPRoute{
				ExtensionRefs: []*ir.UnstructuredRef{{Object: fun}},
			}

			require.NoError(t, (&edgeFunc{}).patchRoute(route, irRoute))

			filterConfigAny := route.GetTypedPerFilterConfig()[edgeFuncFilterName(fun)]
			require.NotNil(t, filterConfigAny)

			filterConfig := &routev3.FilterConfig{}
			require.NoError(t, filterConfigAny.UnmarshalTo(filterConfig))
			configsPerRoute := &golangv3alpha.ConfigsPerRoute{}
			require.NoError(t, filterConfig.GetConfig().UnmarshalTo(configsPerRoute))

			plugin := configsPerRoute.GetPluginsConfig()[tt.wantPluginName]
			require.NotNil(t, plugin)
			pluginConfig := plugin.GetConfig()
			require.NotNil(t, pluginConfig)
			config := &structpb.Struct{}
			require.NoError(t, pluginConfig.UnmarshalTo(config))
			assert.Equal(t, map[string]any{
				"percentage": float64(25),
				"channels": map[string]any{
					"stable": "cluster-a",
				},
			}, config.AsMap())
		})
	}
}

func TestEdgeFuncPatchRouteWithoutDynamicPluginConfig(t *testing.T) {
	fun := edgeFunctionForTest(t, "", "test-filter")
	route := &routev3.Route{}
	irRoute := &ir.HTTPRoute{
		ExtensionRefs: []*ir.UnstructuredRef{{Object: fun}},
	}

	require.NoError(t, (&edgeFunc{}).patchRoute(route, irRoute))

	filterConfig := &routev3.FilterConfig{}
	require.NoError(t, route.GetTypedPerFilterConfig()[edgeFuncFilterName(fun)].UnmarshalTo(filterConfig))
	assert.Empty(t, filterConfig.GetConfig().GetTypeUrl())
}

func TestEdgeFuncPatchRouteRejectsInvalidDynamicPluginConfig(t *testing.T) {
	fun := edgeFunctionForTest(t, "not-an-object", "test-filter")
	route := &routev3.Route{}
	irRoute := &ir.HTTPRoute{
		ExtensionRefs: []*ir.UnstructuredRef{{Object: fun}},
	}

	err := (&edgeFunc{}).patchRoute(route, irRoute)
	require.ErrorContains(t, err, "failed to unmarshal plugin config")
	assert.Empty(t, route.GetTypedPerFilterConfig())
}

func edgeFunctionForTest(t *testing.T, dynamicPluginConfig, pluginName string) *unstructured.Unstructured {
	t.Helper()

	fun := &extensionsv1alpha2.EdgeFunction{
		TypeMeta: metav1.TypeMeta{
			APIVersion: extensionsv1alpha2.SchemeGroupVersion.String(),
			Kind:       "EdgeFunction",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-filter"},
		Spec: extensionsv1alpha2.EdgeFunctionSpec{
			Template: extensionsv1alpha2.EdgeFunctionRevisionSpec{
				Mode: extensionsv1alpha2.FilterEdgeFunctionMode,
				Code: extensionsv1alpha2.EdgeFunctionCodeSource{
					ObjectMeta:     metav1.ObjectMeta{Name: pluginName},
					GoPluginSource: &extensionsv1alpha2.GoPluginSource{},
				},
			},
			DynamicPluginConfig: dynamicPluginConfig,
		},
		Status: extensionsv1alpha2.EdgeFunctionStatus{LiveRevision: "test-filter-abc123"},
	}

	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(fun)
	require.NoError(t, err)
	return &unstructured.Unstructured{Object: object}
}
