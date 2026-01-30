//go:build linux

package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
	"github.com/apoxy-dev/apoxy/pkg/edgefunc"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

// functionDeployerImpl implements FunctionDeployer.
type functionDeployerImpl struct {
	runtimeManager RuntimeManager
	router         FunctionRouter
}

// NewFunctionDeployer creates a new FunctionDeployer.
func NewFunctionDeployer(runtimeManager RuntimeManager, router FunctionRouter) FunctionDeployer {
	return &functionDeployerImpl{
		runtimeManager: runtimeManager,
		router:         router,
	}
}

// Deploy deploys an EdgeFunctionRevision to the appropriate runtime.
func (d *functionDeployerImpl) Deploy(ctx context.Context, namespace Namespace, rev *extensionsv1alpha2.EdgeFunctionRevision) error {
	if rev.Status.Ref == "" {
		return fmt.Errorf("revision has no ref")
	}

	functionID := FunctionID(rev.Status.Ref)
	functionName := rev.Name

	log.Infof("Deploying function %s (id=%s) to namespace %s", functionName, functionID, namespace)

	// Ensure runtime exists for this namespace.
	runtime, err := d.runtimeManager.EnsureRuntime(ctx, namespace)
	if err != nil {
		return fmt.Errorf("failed to ensure runtime: %w", err)
	}

	// Check if function is already deployed and ready.
	if existingFunc, ok := runtime.GetFunction(functionID); ok && existingFunc.Ready {
		log.Infof("Function %s already deployed and ready", functionID)
		// Update the router to point to this function.
		if err := d.router.SetActiveRevision(ctx, namespace, functionName, functionID); err != nil {
			return fmt.Errorf("failed to set active revision: %w", err)
		}
		return nil
	}

	// The eszip file should already be written to the host eszip directory by the reconciler.
	// The path inside the container is /eszips/{functionID}.eszip
	containerEszipPath := filepath.Join("/eszips", string(functionID)+".eszip")

	// Verify eszip file exists on the host.
	hostEszipPath := filepath.Join(runtime.EszipDir, string(functionID)+".eszip")
	if _, err := os.Stat(hostEszipPath); os.IsNotExist(err) {
		return fmt.Errorf("eszip file not found at %s", hostEszipPath)
	}

	// Create client for this runtime.
	client := NewRuntimeClient(runtime.Address, runtime.ControlPort)

	// Upload the function.
	log.Infof("Uploading function %s to runtime %s", functionID, runtime.ContainerID)
	uploadReq := UploadRequest{
		FunctionID:   string(functionID),
		FunctionName: functionName,
		EszipPath:    containerEszipPath,
	}
	if err := client.Upload(ctx, uploadReq); err != nil {
		return fmt.Errorf("failed to upload function: %w", err)
	}

	// Bootstrap the worker.
	log.Infof("Bootstrapping function %s", functionID)
	readyResp, err := client.Ready(ctx, string(functionID))
	if err != nil {
		return fmt.Errorf("failed to bootstrap function: %w", err)
	}

	if !readyResp.Ready {
		return fmt.Errorf("function failed to become ready")
	}

	log.Infof("Function %s ready (cold start: %dms)", functionID, readyResp.ColdStartMs)

	// Update runtime's function info.
	funcInfo := &FunctionInfo{
		FunctionID:   functionID,
		FunctionName: functionName,
		RevisionRef:  rev.Status.Ref,
		EszipPath:    containerEszipPath,
		Ready:        true,
		ColdStartMs:  readyResp.ColdStartMs,
		LoadedAt:     time.Now(),
	}
	runtime.SetFunction(functionID, funcInfo)

	// Update the router to point to this function.
	if err := d.router.SetActiveRevision(ctx, namespace, functionName, functionID); err != nil {
		return fmt.Errorf("failed to set active revision: %w", err)
	}

	return nil
}

// Undeploy removes a function from its runtime.
func (d *functionDeployerImpl) Undeploy(ctx context.Context, namespace Namespace, functionID FunctionID) error {
	log.Infof("Undeploying function %s from namespace %s", functionID, namespace)

	runtime, err := d.runtimeManager.GetRuntime(ctx, namespace)
	if err != nil {
		if err == edgefunc.ErrNotFound {
			log.Infof("Runtime for namespace %s not found, nothing to undeploy", namespace)
			return nil
		}
		return fmt.Errorf("failed to get runtime: %w", err)
	}

	// Get function info to get the function name for router cleanup.
	funcInfo, ok := runtime.GetFunction(functionID)
	if !ok {
		log.Infof("Function %s not found in runtime, nothing to undeploy", functionID)
		return nil
	}

	// Create client for this runtime.
	client := NewRuntimeClient(runtime.Address, runtime.ControlPort)

	// Delete the function from the runtime.
	if err := client.DeleteFunction(ctx, string(functionID)); err != nil {
		log.Warnf("Failed to delete function from runtime: %v", err)
		// Continue anyway to clean up local state.
	}

	// Remove from runtime's function list.
	runtime.DeleteFunction(functionID)

	// Remove from router if this was the active revision.
	// Note: We don't remove from router automatically because another revision
	// might still be active. The router cleanup should be handled by the caller
	// when appropriate.
	_ = funcInfo // Keep for potential future use

	// Remove the eszip file.
	hostEszipPath := filepath.Join(runtime.EszipDir, string(functionID)+".eszip")
	if err := os.Remove(hostEszipPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove eszip file %s: %v", hostEszipPath, err)
	}

	// Also remove the data file if it exists (symlink target).
	hostDataPath := filepath.Join(runtime.EszipDir, string(functionID), "data")
	if err := os.RemoveAll(filepath.Dir(hostDataPath)); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove data directory: %v", err)
	}

	return nil
}

// GetFunctionStatus returns the status of a deployed function.
func (d *functionDeployerImpl) GetFunctionStatus(ctx context.Context, namespace Namespace, functionID FunctionID) (*FunctionInfo, error) {
	runtime, err := d.runtimeManager.GetRuntime(ctx, namespace)
	if err != nil {
		return nil, err
	}

	funcInfo, ok := runtime.GetFunction(functionID)
	if !ok {
		return nil, edgefunc.ErrNotFound
	}

	return funcInfo, nil
}
