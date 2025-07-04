package bootstrap

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRenderedBootstrapConfig(t *testing.T) {
	origDetector := defaultDetector
	defer func() { defaultDetector = origDetector }()

	mockReader := &MockFileReader{
		files: map[string][]byte{
			"/sys/fs/cgroup/memory.max": []byte("2147483648\n"),
		},
	}
	mockDetector := NewCgroupMemoryDetector()
	mockDetector.fileReader = mockReader
	defaultDetector = mockDetector
	result := GetCgroupMemoryLimit()
	assert.Equal(t, uint64(2147483648), result)

	cases := []struct {
		name            string
		overrideOptions []BootstrapOption
	}{
		{
			name: "overload-manager",
			overrideOptions: []BootstrapOption{
				WithOverloadMaxHeapSizeBytes(1073741824), // 1GB
				WithOverloadMaxActiveConnections(50000),
			},
		},
		{
			name: "overload-manager-cgroup",
			overrideOptions: []BootstrapOption{
				WithOverloadMaxActiveConnections(50000),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetRenderedBootstrapConfig(tc.overrideOptions...)
			require.NoError(t, err)

			if *overrideTestData {
				// nolint:gosec
				err = os.WriteFile(path.Join("testdata", "render", fmt.Sprintf("%s.yaml", tc.name)), []byte(got), 0644)
				require.NoError(t, err)
				return
			}

			expected, err := readTestData(tc.name)
			require.NoError(t, err)
			assert.Equal(t, expected, got)
		})
	}
}

func readTestData(caseName string) (string, error) {
	filename := path.Join("testdata", "render", fmt.Sprintf("%s.yaml", caseName))

	b, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
