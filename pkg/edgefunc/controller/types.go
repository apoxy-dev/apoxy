//go:build linux

// Package controller implements the edge function controller that manages
// per-namespace edge runtimes with multiple dynamically-loaded functions.
package controller

import (
	"context"
	"net/netip"
	"sync"
	"time"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

// Namespace represents a logical grouping of functions (e.g., project ID).
type Namespace string

// FunctionID uniquely identifies a function within a namespace.
// Typically derived from the EdgeFunctionRevision ref.
type FunctionID string

// RuntimeInfo contains information about a running edge-runtime container
// for a specific namespace.
type RuntimeInfo struct {
	// Namespace this runtime belongs to.
	Namespace Namespace

	// ContainerID is the container identifier (e.g., "edge-runtime-{namespace}").
	ContainerID string

	// Address is the IPv4 address of the runtime container.
	Address netip.Addr

	// ControlPort is the port for the control API (default 9000).
	ControlPort int

	// ServicePort is the port for serving requests (default 8080).
	ServicePort int

	// EszipDir is the host directory where eszip files are stored for this runtime.
	EszipDir string

	// Functions maps function IDs to their info for functions loaded in this runtime.
	Functions map[FunctionID]*FunctionInfo

	// CreatedAt is when the runtime was created.
	CreatedAt time.Time

	// mu protects Functions map.
	mu sync.RWMutex
}

// GetFunction returns function info by ID, thread-safe.
func (r *RuntimeInfo) GetFunction(id FunctionID) (*FunctionInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.Functions[id]
	return f, ok
}

// SetFunction sets function info, thread-safe.
func (r *RuntimeInfo) SetFunction(id FunctionID, info *FunctionInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Functions[id] = info
}

// DeleteFunction removes function info, thread-safe.
func (r *RuntimeInfo) DeleteFunction(id FunctionID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.Functions, id)
}

// ListFunctions returns all function IDs in this runtime, thread-safe.
func (r *RuntimeInfo) ListFunctions() []FunctionID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]FunctionID, 0, len(r.Functions))
	for id := range r.Functions {
		ids = append(ids, id)
	}
	return ids
}

// FunctionInfo contains information about a function loaded in a runtime.
type FunctionInfo struct {
	// FunctionID is the unique identifier for this function.
	FunctionID FunctionID

	// FunctionName is the human-readable name of the function.
	FunctionName string

	// RevisionRef is the EdgeFunctionRevision ref (e.g., hash of the code).
	RevisionRef string

	// EszipPath is the path to the eszip file inside the container.
	EszipPath string

	// Ready indicates whether the function has been bootstrapped and is ready to serve.
	Ready bool

	// ColdStartMs is the cold start time in milliseconds (from /_internal/ready response).
	ColdStartMs int64

	// LoadedAt is when the function was loaded into the runtime.
	LoadedAt time.Time
}

// UploadRequest is the request body for /_internal/upload.
type UploadRequest struct {
	FunctionID   string `json:"function_id"`
	FunctionName string `json:"function_name"`
	EszipPath    string `json:"eszip_path"`
}

// ReadyRequest is the request body for /_internal/ready.
type ReadyRequest struct {
	FunctionID string `json:"function_id"`
}

// ReadyResponse is the response body from /_internal/ready.
type ReadyResponse struct {
	Ready       bool  `json:"ready"`
	ColdStartMs int64 `json:"cold_start_ms"`
}

// HealthResponse is the response body from /_internal/health.
type HealthResponse struct {
	Functions map[string]FunctionHealthStatus `json:"functions"`
}

// FunctionHealthStatus represents the health status of a single function.
type FunctionHealthStatus struct {
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

// RuntimeManager manages the lifecycle of per-namespace edge-runtime containers.
type RuntimeManager interface {
	// EnsureRuntime ensures a runtime exists for the given namespace.
	// Creates one if it doesn't exist.
	EnsureRuntime(ctx context.Context, namespace Namespace) (*RuntimeInfo, error)

	// GetRuntime returns the runtime info for a namespace, or nil if not exists.
	GetRuntime(ctx context.Context, namespace Namespace) (*RuntimeInfo, error)

	// TerminateRuntime stops and removes the runtime for a namespace.
	TerminateRuntime(ctx context.Context, namespace Namespace) error

	// ListRuntimes returns all active runtimes.
	ListRuntimes(ctx context.Context) ([]*RuntimeInfo, error)
}

// FunctionDeployer handles deploying functions to runtimes.
type FunctionDeployer interface {
	// Deploy deploys an EdgeFunctionRevision to the appropriate runtime.
	Deploy(ctx context.Context, namespace Namespace, rev *extensionsv1alpha2.EdgeFunctionRevision) error

	// Undeploy removes a function from its runtime.
	Undeploy(ctx context.Context, namespace Namespace, functionID FunctionID) error

	// GetFunctionStatus returns the status of a deployed function.
	GetFunctionStatus(ctx context.Context, namespace Namespace, functionID FunctionID) (*FunctionInfo, error)
}

// FunctionRouter tracks active function→runtime mappings and provides resolution.
type FunctionRouter interface {
	// Resolve returns the FunctionID for a given function name in a namespace.
	// Returns the currently active revision's function ID.
	Resolve(ctx context.Context, namespace Namespace, functionName string) (FunctionID, error)

	// SetActiveRevision sets the active function ID for a function name.
	SetActiveRevision(ctx context.Context, namespace Namespace, functionName string, functionID FunctionID) error

	// GetRuntimeAddress returns the address and service port for a namespace's runtime.
	GetRuntimeAddress(ctx context.Context, namespace Namespace) (address netip.Addr, port int, err error)

	// RemoveFunction removes a function name mapping.
	RemoveFunction(ctx context.Context, namespace Namespace, functionName string) error
}

// RuntimeClient is the interface for communicating with an edge-runtime's control API.
type RuntimeClient interface {
	// Upload registers a new function with the runtime.
	Upload(ctx context.Context, req UploadRequest) error

	// Ready bootstraps a worker for the function and returns readiness status.
	Ready(ctx context.Context, functionID string) (*ReadyResponse, error)

	// Health returns the health status of all functions in the runtime.
	Health(ctx context.Context) (*HealthResponse, error)

	// DeleteFunction unloads a function from the runtime.
	DeleteFunction(ctx context.Context, functionID string) error
}
