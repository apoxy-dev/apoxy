//go:build linux

package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/edgefunc"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc/runc/network"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	// containerPrefix is the prefix for edge-runtime container IDs.
	containerPrefix = "edge-runtime-"
)

// ContainerRuntime is the interface for creating and managing containers.
// This abstracts the runc runtime to allow for testing and potential future
// implementations (e.g., containerd, docker).
type ContainerRuntime interface {
	// ExecNamespace creates and starts a new edge-runtime container for a namespace.
	ExecNamespace(ctx context.Context, id string, eszipDir string, servicePort, controlPort int) error

	// StopExec stops the execution of a container.
	StopExec(ctx context.Context, id string) error

	// DeleteExec deletes a container.
	DeleteExec(ctx context.Context, id string) error

	// ExecStatus returns the status of a container.
	ExecStatus(ctx context.Context, id string) (edgefunc.Status, error)

	// ListExecs returns all container executions.
	ListExecs(ctx context.Context) ([]edgefunc.Status, error)

	// Network returns the network manager for the runtime.
	Network() *network.Network
}

// runtimeManagerImpl implements RuntimeManager.
type runtimeManagerImpl struct {
	containerRuntime ContainerRuntime
	baseEszipDir     string

	// runtimes maps namespace to runtime info.
	runtimes map[Namespace]*RuntimeInfo
	mu       sync.RWMutex
}

// RuntimeManagerOption configures a RuntimeManager.
type RuntimeManagerOption func(*runtimeManagerImpl)

// WithBaseEszipDir sets the base directory for eszip files.
func WithBaseEszipDir(dir string) RuntimeManagerOption {
	return func(m *runtimeManagerImpl) {
		m.baseEszipDir = dir
	}
}

// NewRuntimeManager creates a new RuntimeManager.
func NewRuntimeManager(containerRuntime ContainerRuntime, opts ...RuntimeManagerOption) RuntimeManager {
	m := &runtimeManagerImpl{
		containerRuntime: containerRuntime,
		baseEszipDir:     "/var/lib/apoxy/eszips",
		runtimes:         make(map[Namespace]*RuntimeInfo),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// containerID returns the container ID for a namespace.
func containerID(ns Namespace) string {
	return containerPrefix + string(ns)
}

// eszipDir returns the eszip directory for a namespace.
func (m *runtimeManagerImpl) eszipDir(ns Namespace) string {
	return filepath.Join(m.baseEszipDir, string(ns))
}

// EnsureRuntime ensures a runtime exists for the given namespace.
func (m *runtimeManagerImpl) EnsureRuntime(ctx context.Context, namespace Namespace) (*RuntimeInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if runtime already exists in our cache.
	if info, ok := m.runtimes[namespace]; ok {
		// Verify container is still running.
		status, err := m.containerRuntime.ExecStatus(ctx, info.ContainerID)
		if err == nil && status.State == edgefunc.StateRunning {
			return info, nil
		}
		// Container is not running, clean up and recreate.
		log.Infof("Runtime %s not running (state=%s), recreating", info.ContainerID, status.State)
		delete(m.runtimes, namespace)
	}

	cid := containerID(namespace)
	eszipDir := m.eszipDir(namespace)

	// Check if container exists but we don't have it in cache.
	status, err := m.containerRuntime.ExecStatus(ctx, cid)
	if err == nil && status.State == edgefunc.StateRunning {
		log.Infof("Found existing running runtime %s", cid)
		// Recover runtime info from existing container.
		info, err := m.recoverRuntimeInfo(ctx, namespace, cid, eszipDir)
		if err != nil {
			return nil, fmt.Errorf("failed to recover runtime info: %w", err)
		}
		m.runtimes[namespace] = info
		return info, nil
	}

	// Create eszip directory if it doesn't exist.
	if err := os.MkdirAll(eszipDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create eszip directory: %w", err)
	}

	log.Infof("Creating new runtime for namespace %s (container=%s)", namespace, cid)

	// Create the container.
	if err := m.containerRuntime.ExecNamespace(ctx, cid, eszipDir, DefaultServicePort, DefaultControlPort); err != nil {
		return nil, fmt.Errorf("failed to create runtime container: %w", err)
	}

	// Get the container's IP address from the network.
	sandboxInfo, err := m.containerRuntime.Network().Status(ctx, cid)
	if err != nil {
		// Clean up on failure.
		_ = m.containerRuntime.StopExec(ctx, cid)
		_ = m.containerRuntime.DeleteExec(ctx, cid)
		return nil, fmt.Errorf("failed to get container network info: %w", err)
	}

	info := &RuntimeInfo{
		Namespace:   namespace,
		ContainerID: cid,
		Address:     sandboxInfo.IP,
		ControlPort: DefaultControlPort,
		ServicePort: DefaultServicePort,
		EszipDir:    eszipDir,
		Functions:   make(map[FunctionID]*FunctionInfo),
		CreatedAt:   time.Now(),
	}

	m.runtimes[namespace] = info

	log.Infof("Created runtime for namespace %s at %s", namespace, sandboxInfo.IP)

	return info, nil
}

// recoverRuntimeInfo recovers RuntimeInfo from an existing container.
func (m *runtimeManagerImpl) recoverRuntimeInfo(ctx context.Context, namespace Namespace, cid, eszipDir string) (*RuntimeInfo, error) {
	sandboxInfo, err := m.containerRuntime.Network().Status(ctx, cid)
	if err != nil {
		return nil, fmt.Errorf("failed to get container network info: %w", err)
	}

	info := &RuntimeInfo{
		Namespace:   namespace,
		ContainerID: cid,
		Address:     sandboxInfo.IP,
		ControlPort: DefaultControlPort,
		ServicePort: DefaultServicePort,
		EszipDir:    eszipDir,
		Functions:   make(map[FunctionID]*FunctionInfo),
		CreatedAt:   time.Now(), // We don't know the actual creation time.
	}

	// Try to recover function info from the runtime's health endpoint.
	client := NewRuntimeClient(sandboxInfo.IP, DefaultControlPort)
	health, err := client.Health(ctx)
	if err != nil {
		log.Warnf("Failed to get health from recovered runtime: %v", err)
		return info, nil
	}

	for funcID, status := range health.Functions {
		info.Functions[FunctionID(funcID)] = &FunctionInfo{
			FunctionID: FunctionID(funcID),
			Ready:      status.Ready,
		}
	}

	return info, nil
}

// GetRuntime returns the runtime info for a namespace.
func (m *runtimeManagerImpl) GetRuntime(ctx context.Context, namespace Namespace) (*RuntimeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, ok := m.runtimes[namespace]
	if !ok {
		return nil, edgefunc.ErrNotFound
	}

	// Verify container is still running.
	status, err := m.containerRuntime.ExecStatus(ctx, info.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container status: %w", err)
	}
	if status.State != edgefunc.StateRunning {
		return nil, fmt.Errorf("runtime not running (state=%s)", status.State)
	}

	return info, nil
}

// TerminateRuntime stops and removes the runtime for a namespace.
func (m *runtimeManagerImpl) TerminateRuntime(ctx context.Context, namespace Namespace) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.runtimes[namespace]
	if !ok {
		// Try to find container by ID anyway.
		cid := containerID(namespace)
		if _, err := m.containerRuntime.ExecStatus(ctx, cid); err != nil {
			return edgefunc.ErrNotFound
		}
		info = &RuntimeInfo{ContainerID: cid}
	}

	log.Infof("Terminating runtime %s for namespace %s", info.ContainerID, namespace)

	// Stop the container.
	if err := m.containerRuntime.StopExec(ctx, info.ContainerID); err != nil {
		log.Warnf("Failed to stop container %s: %v", info.ContainerID, err)
	}

	// Wait a bit for graceful shutdown.
	time.Sleep(2 * time.Second)

	// Delete the container.
	if err := m.containerRuntime.DeleteExec(ctx, info.ContainerID); err != nil {
		log.Warnf("Failed to delete container %s: %v", info.ContainerID, err)
	}

	// Clean up eszip directory.
	eszipDir := m.eszipDir(namespace)
	if err := os.RemoveAll(eszipDir); err != nil {
		log.Warnf("Failed to remove eszip directory %s: %v", eszipDir, err)
	}

	delete(m.runtimes, namespace)

	return nil
}

// ListRuntimes returns all active runtimes.
func (m *runtimeManagerImpl) ListRuntimes(ctx context.Context) ([]*RuntimeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	runtimes := make([]*RuntimeInfo, 0, len(m.runtimes))
	for _, info := range m.runtimes {
		runtimes = append(runtimes, info)
	}
	return runtimes, nil
}
