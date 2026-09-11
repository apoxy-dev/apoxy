package gateway

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// The apiserver bumps metadata.generation only when the object's Spec field
// changes, so a kind without a Spec field can never leave generation zero and
// every generation predicate on it drops all updates.
func TestGenerationTrackedObjectsHaveSpec(t *testing.T) {
	objs := GenerationTrackedObjects()
	require.Len(t, objs, len(generationTracked))

	for _, obj := range objs {
		name := reflect.TypeOf(obj).String()
		t.Run(name, func(t *testing.T) {
			v := reflect.ValueOf(obj)
			require.Equal(t, reflect.Pointer, v.Kind())
			v = v.Elem()
			require.Equal(t, reflect.Struct, v.Kind())
			assert.True(t, v.FieldByName("Spec").IsValid(), "%s has no Spec field", name)

			gvr := obj.GetGroupVersionResource()
			assert.NotEmpty(t, gvr.Version)
			assert.NotEmpty(t, gvr.Resource)
		})
	}
}

func TestGenerationTrackedObjectsAreUnique(t *testing.T) {
	seen := make(map[schema.GroupVersionResource]string)
	for _, obj := range GenerationTrackedObjects() {
		gvr := obj.GetGroupVersionResource()
		name := reflect.TypeOf(obj).String()
		first, dup := seen[gvr]
		assert.False(t, dup, "%s repeats %s at %s", name, first, gvr)
		seen[gvr] = name
	}
}

// Every watched kind needs a predicate. A nil predicate makes the watch
// pass all updates, which restarts the status-write amplification loop.
func TestGenerationTrackedWatchesHavePredicates(t *testing.T) {
	for _, tk := range generationTracked {
		name := reflect.TypeOf(tk.obj).String()
		t.Run(name, func(t *testing.T) {
			if !tk.watch {
				t.Skip("not watched")
			}
			assert.NotNil(t, tk.pred)
		})
	}
}
