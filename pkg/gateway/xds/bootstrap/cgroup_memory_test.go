package bootstrap

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// MockFileReader implements FileReader for testing
type MockFileReader struct {
	files map[string][]byte
}

// ReadFile mocks reading a file
func (r *MockFileReader) ReadFile(filename string) ([]byte, error) {
	if content, ok := r.files[filename]; ok {
		return content, nil
	}
	return nil, os.ErrNotExist
}

// Open is not implemented for the mock
func (r *MockFileReader) Open(name string) (*os.File, error) {
	return nil, os.ErrNotExist // Not needed for our tests
}

// mockDetector is a mock implementation for testing
type mockDetector struct {
	memLimit uint64
}

// GetMemoryLimit returns the mock memory limit
func (d *mockDetector) GetMemoryLimit() uint64 {
	return d.memLimit
}

// GetDefaultMaxHeapSizeBytes returns a fixed heap size for testing
func (d *mockDetector) GetDefaultMaxHeapSizeBytes() *uint64 {
	if d.memLimit > 0 {
		// Use 80% of the memory limit as the max heap size
		heapSize := uint64(float64(d.memLimit) * 0.8)
		return &heapSize
	}
	return nil
}

func TestCgroupMemoryDetector_GetMemoryLimit(t *testing.T) {
	// Create a mock file reader
	mockReader := &MockFileReader{
		files: make(map[string][]byte),
	}

	// Create a detector with the mock reader
	detector := NewCgroupMemoryDetector()
	detector.fileReader = mockReader

	// Test cases
	testCases := []struct {
		name           string
		setupFunc      func()
		expectedResult uint64
	}{
		{
			name: "cgroup v2 unified path",
			setupFunc: func() {
				// Clear previous test files
				mockReader.files = make(map[string][]byte)
				// Add mock cgroup v2 file
				mockReader.files[detector.cgroupV2UnifiedPath] = []byte("2147483648\n")
			},
			expectedResult: 2147483648, // 2GB
		},
		{
			name: "cgroup v1 path",
			setupFunc: func() {
				// Clear previous test files
				mockReader.files = make(map[string][]byte)
				// Add mock cgroup v1 file
				mockReader.files[detector.cgroupV1Path] = []byte("1073741824\n")
			},
			expectedResult: 1073741824, // 1GB
		},
		{
			name: "cgroup v2 max value (unlimited)",
			setupFunc: func() {
				// Clear previous test files
				mockReader.files = make(map[string][]byte)
				// Add mock cgroup v2 file with "max" value
				mockReader.files[detector.cgroupV2UnifiedPath] = []byte("max\n")
			},
			expectedResult: 0, // "max" means no limit
		},
		{
			name: "no cgroup files",
			setupFunc: func() {
				// Clear all files
				mockReader.files = make(map[string][]byte)
			},
			expectedResult: 0, // No limit detected
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFunc()
			result := detector.GetMemoryLimit()
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestGetCgroupMemoryLimit(t *testing.T) {
	// Save the original detector
	origDetector := defaultDetector
	defer func() { defaultDetector = origDetector }()

	// Create a mock detector
	mockReader := &MockFileReader{
		files: map[string][]byte{
			"/sys/fs/cgroup/memory.max": []byte("2147483648\n"),
		},
	}

	mockDetector := NewCgroupMemoryDetector()
	mockDetector.fileReader = mockReader

	// Replace the default detector
	defaultDetector = mockDetector

	// Test the function
	result := GetCgroupMemoryLimit()
	assert.Equal(t, uint64(2147483648), result)
}

func TestGetDefaultMaxHeapSizeBytes(t *testing.T) {
	// Save the original detector
	origDetector := defaultDetector
	defer func() { defaultDetector = origDetector }()

	testCases := []struct {
		name           string
		memoryLimit    uint64
		expectedResult *uint64
	}{
		{
			name:        "with memory limit",
			memoryLimit: 2147483648, // 2GB
			expectedResult: func() *uint64 {
				val := uint64(2147483648)
				return &val
			}(),
		},
		{
			name:           "no memory limit",
			memoryLimit:    0,
			expectedResult: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock detector with a custom implementation
			mockDetector := &mockDetector{
				memLimit: tc.memoryLimit,
			}
			defaultDetector = mockDetector

			result := GetDefaultMaxHeapSizeBytes()

			if tc.expectedResult == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, *tc.expectedResult, *result)
			}
		})
	}
}
