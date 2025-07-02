package bootstrap

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

// FileReader is an interface for reading files, used for testing
type FileReader interface {
	ReadFile(filename string) ([]byte, error)
	Open(name string) (*os.File, error)
}

// DefaultFileReader is the default implementation of FileReader
type DefaultFileReader struct{}

// ReadFile reads a file using os.ReadFile
func (r DefaultFileReader) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// Open opens a file using os.Open
func (r DefaultFileReader) Open(name string) (*os.File, error) {
	return os.Open(name)
}

// CgroupMemoryDetector detects cgroup memory limits
type CgroupMemoryDetector struct {
	fileReader FileReader
	// cgroup paths
	cgroupV1Path        string
	cgroupV2Path        string
	cgroupV2UnifiedPath string
	cgroupV1ProcPath    string
	cgroupV2ProcPath    string
}

// NewCgroupMemoryDetector creates a new CgroupMemoryDetector with default paths
func NewCgroupMemoryDetector() *CgroupMemoryDetector {
	return &CgroupMemoryDetector{
		fileReader:          DefaultFileReader{},
		cgroupV1Path:        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
		cgroupV2Path:        "/sys/fs/cgroup/memory.max",
		cgroupV2UnifiedPath: "/sys/fs/cgroup/memory.max",
		cgroupV1ProcPath:    "/proc/self/cgroup",
		cgroupV2ProcPath:    "/proc/self/mountinfo",
	}
}

// GetMemoryLimit returns the cgroup memory limit in bytes.
// It tries to detect both cgroup v1 and v2 memory limits.
// If no limit is found, it returns 0.
func (d *CgroupMemoryDetector) GetMemoryLimit() uint64 {
	// Try cgroup v2 first
	memLimit, err := d.getCgroupV2MemoryLimit()
	if err == nil && memLimit > 0 {
		log.Infof("Successfully read cgroup v2 memory limit: %d bytes", memLimit)
		return memLimit
	}

	// Fall back to cgroup v1
	memLimit, err = d.getCgroupV1MemoryLimit()
	if err == nil && memLimit > 0 {
		log.Infof("Successfully read cgroup v1 memory limit: %d bytes", memLimit)
		return memLimit
	}

	log.Infof("Could not detect cgroup memory limit, using default")
	return 0
}

// GetDefaultMaxHeapSizeBytes returns the default max heap size in bytes based on cgroup memory limit
func (d *CgroupMemoryDetector) GetDefaultMaxHeapSizeBytes() *uint64 {
	memLimit := d.GetMemoryLimit()
	if memLimit > 0 {
		return &memLimit
	}
	return nil
}

// getCgroupV2MemoryLimit returns the cgroup v2 memory limit in bytes.
func (d *CgroupMemoryDetector) getCgroupV2MemoryLimit() (uint64, error) {
	// First try the unified hierarchy
	content, err := d.fileReader.ReadFile(d.cgroupV2UnifiedPath)
	if err == nil {
		return d.parseCgroupMemoryValue(string(content))
	}

	// Try to find the cgroup path from mountinfo
	cgroupPath, err := d.detectCgroupV2Path()
	if err != nil {
		return 0, err
	}

	// Read the memory.max file
	memLimitPath := filepath.Join(cgroupPath, "memory.max")
	content, err = d.fileReader.ReadFile(memLimitPath)
	if err != nil {
		return 0, err
	}

	return d.parseCgroupMemoryValue(string(content))
}

// getCgroupV1MemoryLimit returns the cgroup v1 memory limit in bytes.
func (d *CgroupMemoryDetector) getCgroupV1MemoryLimit() (uint64, error) {
	// First try the default path
	content, err := d.fileReader.ReadFile(d.cgroupV1Path)
	if err == nil {
		return d.parseCgroupMemoryValue(string(content))
	}

	// Try to find the cgroup path from /proc/self/cgroup
	cgroupPath, err := d.detectCgroupV1Path()
	if err != nil {
		return 0, err
	}

	// Read the memory.limit_in_bytes file
	memLimitPath := filepath.Join("/sys/fs/cgroup/memory", cgroupPath, "memory.limit_in_bytes")
	content, err = d.fileReader.ReadFile(memLimitPath)
	if err != nil {
		return 0, err
	}

	return d.parseCgroupMemoryValue(string(content))
}

// detectCgroupV1Path returns the cgroup path for the current process in cgroup v1.
func (d *CgroupMemoryDetector) detectCgroupV1Path() (string, error) {
	file, err := d.fileReader.Open(d.cgroupV1ProcPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 3 && strings.Contains(parts[1], "memory") {
			return parts[2], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("memory controller not found in cgroup v1")
}

// detectCgroupV2Path returns the cgroup path for the current process in cgroup v2.
func (d *CgroupMemoryDetector) detectCgroupV2Path() (string, error) {
	file, err := d.fileReader.Open(d.cgroupV2ProcPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[4] == "cgroup2" {
			return fields[4], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("cgroup2 mount point not found")
}

// parseCgroupMemoryValue parses the memory value from cgroup files.
// It handles "max" value (which means unlimited) and converts to uint64.
func (d *CgroupMemoryDetector) parseCgroupMemoryValue(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "max" {
		return 0, nil // "max" means no limit
	}

	memLimit, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, err
	}

	// Sanity check: if the value is unreasonably large or small, ignore it
	if memLimit < 1024*1024 || memLimit > 1024*1024*1024*1024 {
		return 0, fmt.Errorf("memory limit value out of reasonable range: %d", memLimit)
	}

	return memLimit, nil
}

// MemoryDetector is an interface for memory limit detection
type MemoryDetector interface {
	GetMemoryLimit() uint64
	GetDefaultMaxHeapSizeBytes() *uint64
}

// Global instance of the detector for convenience
var defaultDetector MemoryDetector = NewCgroupMemoryDetector()

// GetCgroupMemoryLimit returns the cgroup memory limit using the default detector
func GetCgroupMemoryLimit() uint64 {
	return defaultDetector.GetMemoryLimit()
}

// GetDefaultMaxHeapSizeBytes returns the default max heap size in bytes based on cgroup memory limit
func GetDefaultMaxHeapSizeBytes() *uint64 {
	memLimit := GetCgroupMemoryLimit()
	if memLimit > 0 {
		return &memLimit
	}
	return nil
}
