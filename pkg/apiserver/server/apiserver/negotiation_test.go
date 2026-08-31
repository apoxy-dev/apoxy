package apiserver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

func TestWithJSONAndYAML(t *testing.T) {
	restricted := WithJSONAndYAML(serializer.NewCodecFactory(NewScheme()))

	var gotTypes []string
	for _, info := range restricted.SupportedMediaTypes() {
		gotTypes = append(gotTypes, info.MediaType)
	}

	require.Equal(t, []string{runtime.ContentTypeJSON, runtime.ContentTypeYAML}, gotTypes)
}
