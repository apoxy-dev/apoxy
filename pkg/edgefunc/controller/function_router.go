//go:build linux

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/edgefunc"
)

// functionRouterImpl implements FunctionRouter.
type functionRouterImpl struct {
	runtimeManager RuntimeManager

	// activeFunctions maps namespace+functionName to FunctionID.
	// Key format: "{namespace}/{functionName}"
	activeFunctions map[string]FunctionID
	mu              sync.RWMutex
}

// NewFunctionRouter creates a new FunctionRouter.
func NewFunctionRouter(runtimeManager RuntimeManager) FunctionRouter {
	return &functionRouterImpl{
		runtimeManager:  runtimeManager,
		activeFunctions: make(map[string]FunctionID),
	}
}

// routerKey creates a key for the activeFunctions map.
func routerKey(namespace Namespace, functionName string) string {
	return string(namespace) + "/" + functionName
}

// Resolve returns the FunctionID for a given function name in a namespace.
func (r *functionRouterImpl) Resolve(ctx context.Context, namespace Namespace, functionName string) (FunctionID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := routerKey(namespace, functionName)
	funcID, ok := r.activeFunctions[key]
	if !ok {
		return "", edgefunc.ErrNotFound
	}

	return funcID, nil
}

// SetActiveRevision sets the active function ID for a function name.
func (r *functionRouterImpl) SetActiveRevision(ctx context.Context, namespace Namespace, functionName string, functionID FunctionID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := routerKey(namespace, functionName)
	r.activeFunctions[key] = functionID

	return nil
}

// GetRuntimeAddress returns the address and service port for a namespace's runtime.
func (r *functionRouterImpl) GetRuntimeAddress(ctx context.Context, namespace Namespace) (netip.Addr, int, error) {
	runtime, err := r.runtimeManager.GetRuntime(ctx, namespace)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("failed to get runtime: %w", err)
	}

	return runtime.Address, runtime.ServicePort, nil
}

// RemoveFunction removes a function name mapping.
func (r *functionRouterImpl) RemoveFunction(ctx context.Context, namespace Namespace, functionName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := routerKey(namespace, functionName)
	delete(r.activeFunctions, key)

	return nil
}

// ListActiveFunctions returns all active function mappings (for debugging/monitoring).
func (r *functionRouterImpl) ListActiveFunctions() map[string]FunctionID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]FunctionID, len(r.activeFunctions))
	for k, v := range r.activeFunctions {
		result[k] = v
	}
	return result
}
