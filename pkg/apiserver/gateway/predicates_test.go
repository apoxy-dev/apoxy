package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	gatewayv1 "github.com/apoxy-dev/apoxy/api/gateway/v1"
)

var deletedAt = metav1.NewTime(metav1.Now().Time)

// route returns an HTTPRoute with the given generation and resourceVersion.
func route(generation int64, resourceVersion string, deleting bool) *gatewayv1.HTTPRoute {
	r := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "route",
			Generation:      generation,
			ResourceVersion: resourceVersion,
		},
	}
	if deleting {
		r.DeletionTimestamp = deletedAt.DeepCopy()
		r.Finalizers = []string{"apoxy.dev/test"}
	}
	return r
}

// edgeFunc returns an EdgeFunction with the given generation and live revision.
func edgeFunc(generation int64, liveRevision string, deleting bool) *extensionsv1alpha2.EdgeFunction {
	f := &extensionsv1alpha2.EdgeFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "func",
			Generation: generation,
		},
		Status: extensionsv1alpha2.EdgeFunctionStatus{
			LiveRevision: liveRevision,
		},
	}
	if deleting {
		f.DeletionTimestamp = deletedAt.DeepCopy()
		f.Finalizers = []string{"apoxy.dev/test"}
	}
	return f
}

func TestGenerationOrDeletion(t *testing.T) {
	cases := []struct {
		name string
		old  client.Object
		new  client.Object
		want bool
	}{
		{
			name: "spec change bumps generation",
			old:  route(1, "10", false),
			new:  route(2, "11", false),
			want: true,
		},
		{
			name: "status-only write keeps the generation",
			old:  route(1, "10", false),
			new:  route(1, "11", false),
			want: false,
		},
		{
			name: "deletion request sets deletionTimestamp",
			old:  route(1, "10", false),
			new:  route(1, "11", true),
			want: true,
		},
		{
			name: "already deleting",
			old:  route(1, "10", true),
			new:  route(1, "11", true),
			want: false,
		},
		{
			name: "nil old object",
			old:  nil,
			new:  route(2, "11", false),
			want: false,
		},
		{
			name: "nil new object",
			old:  route(1, "10", false),
			new:  nil,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := generationOrDeletion.Update(event.UpdateEvent{ObjectOld: tc.old, ObjectNew: tc.new})
			assert.Equal(t, tc.want, got)
		})
	}

	// Create, Delete and Generic events keep the default (pass) behavior.
	assert.True(t, generationOrDeletion.Create(event.CreateEvent{Object: route(1, "10", false)}))
	assert.True(t, generationOrDeletion.Delete(event.DeleteEvent{Object: route(1, "10", false)}))
	assert.True(t, generationOrDeletion.Generic(event.GenericEvent{Object: route(1, "10", false)}))
}

func TestEdgeFunctionRetrigger(t *testing.T) {
	cases := []struct {
		name string
		old  client.Object
		new  client.Object
		want bool
	}{
		{
			name: "spec change bumps generation",
			old:  edgeFunc(1, "rev-1", false),
			new:  edgeFunc(2, "rev-1", false),
			want: true,
		},
		{
			name: "new live revision",
			old:  edgeFunc(1, "rev-1", false),
			new:  edgeFunc(1, "rev-2", false),
			want: true,
		},
		{
			name: "first live revision",
			old:  edgeFunc(1, "", false),
			new:  edgeFunc(1, "rev-1", false),
			want: true,
		},
		{
			name: "no change",
			old:  edgeFunc(1, "rev-1", false),
			new:  edgeFunc(1, "rev-1", false),
			want: false,
		},
		{
			name: "deletion request sets deletionTimestamp",
			old:  edgeFunc(1, "rev-1", false),
			new:  edgeFunc(1, "rev-1", true),
			want: true,
		},
		{
			name: "already deleting",
			old:  edgeFunc(1, "rev-1", true),
			new:  edgeFunc(1, "rev-1", true),
			want: false,
		},
		{
			name: "other kind",
			old:  route(1, "10", false),
			new:  route(2, "11", false),
			want: false,
		},
		{
			name: "nil old object",
			old:  nil,
			new:  edgeFunc(2, "rev-1", false),
			want: false,
		},
		{
			name: "nil new object",
			old:  edgeFunc(1, "rev-1", false),
			new:  nil,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := edgeFunctionRetrigger.Update(event.UpdateEvent{ObjectOld: tc.old, ObjectNew: tc.new})
			assert.Equal(t, tc.want, got)
		})
	}

	assert.True(t, edgeFunctionRetrigger.Create(event.CreateEvent{Object: edgeFunc(1, "rev-1", false)}))
	assert.True(t, edgeFunctionRetrigger.Delete(event.DeleteEvent{Object: edgeFunc(1, "rev-1", false)}))
	assert.True(t, edgeFunctionRetrigger.Generic(event.GenericEvent{Object: edgeFunc(1, "rev-1", false)}))
}
