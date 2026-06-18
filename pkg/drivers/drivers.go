// Package drivers implements common interfaces and utilities for Apoxy service drivers
package drivers

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Option is a function that configures driver options.
type Option func(*Options)

// Options contains common options for all drivers.
type Options struct {
	Args          []string
	APIServerAddr string
	// NetworkContainer, when set, joins the container's network namespace
	// (`docker run --network container:<name>`) instead of the apoxy bridge. The
	// workerd-manager uses this to share the apiserver's netns so its publish and
	// kube-API traffic reach the apiserver over loopback.
	NetworkContainer string
	// WorkerdSocketVolume, when set, is a Docker volume mounted at
	// /run/workerd-manager in both the backplane and the workerd-manager, so the
	// backplane's Envoy can dial the resident workerd's host UDS the manager
	// surfaces there.
	WorkerdSocketVolume string
}

// DefaultOptions returns the default options.
func DefaultOptions() *Options {
	return &Options{}
}

// WithArgs sets the arguments for the driver.
func WithArgs(args ...string) Option {
	return func(o *Options) {
		o.Args = args
	}
}

// WithAPIServerAddr sets the apiserver address.
func WithAPIServerAddr(addr string) Option {
	return func(o *Options) {
		o.APIServerAddr = addr
	}
}

// WithNetworkContainer joins another container's network namespace.
func WithNetworkContainer(name string) Option {
	return func(o *Options) {
		o.NetworkContainer = name
	}
}

// WithWorkerdSocketVolume mounts the shared resident-socket volume.
func WithWorkerdSocketVolume(name string) Option {
	return func(o *Options) {
		o.WorkerdSocketVolume = name
	}
}

// Driver is the interface that all service drivers must implement.
type Driver interface {
	// Start deploys and starts the service.
	Start(ctx context.Context, orgID uuid.UUID, serviceName string, opts ...Option) (string, error)
	// Stop stops the service.
	Stop(orgID uuid.UUID, serviceName string)
	// GetAddr returns the address of the service.
	GetAddr(ctx context.Context) (string, error)
}

// ServiceType represents the type of service being managed by a driver.
type ServiceType string

// DriverMode represents the mode in which the driver is running.
type DriverMode string

const (
	// BackplaneService represents the backplane service.
	BackplaneService ServiceType = "backplane"
	// APIServerService represents the apiserver service.
	APIServerService ServiceType = "apiserver"
	// TunnelProxyService represents the tunnel proxy service.
	TunnelProxyService ServiceType = "tunnelproxy"
	// WorkerdManagerService represents the workerd-manager service (APO-796): the
	// privileged/runsc data-plane sidecar that runs the shared resident workerd.
	WorkerdManagerService ServiceType = "workerd-manager"

	// DockerMode represents the docker driver mode.
	DockerMode DriverMode = "docker"
	// SupervisorMode represents the supervisor driver mode.
	SupervisorMode DriverMode = "supervisor"
)

// GetDriver returns a driver by name for the specified service type.
func GetDriver(driverType DriverMode, serviceType ServiceType) (Driver, error) {
	switch serviceType {
	case BackplaneService:
		return GetBackplaneDriver(driverType)
	case APIServerService:
		return GetAPIServerDriver(driverType)
	case TunnelProxyService:
		return GetTunnelProxyDriver(driverType)
	case WorkerdManagerService:
		return GetWorkerdManagerDriver(driverType)
	default:
		return nil, fmt.Errorf("unknown service type %q", serviceType)
	}
}

// GetWorkerdManagerDriver returns a workerd-manager driver by mode. Only
// DockerMode is supported: the manager needs a privileged gVisor-capable
// container, which the subprocess/supervisor path cannot provide.
func GetWorkerdManagerDriver(driver DriverMode) (Driver, error) {
	switch driver {
	case DockerMode:
		return NewWorkerdManagerDockerDriver(), nil
	default:
		return nil, fmt.Errorf("workerd-manager only supports the docker driver, got %q", driver)
	}
}

// GetBackplaneDriver returns a backplane driver by name.
func GetBackplaneDriver(driver DriverMode) (Driver, error) {
	switch driver {
	case DockerMode:
		return NewBackplaneDockerDriver(), nil
	case SupervisorMode:
		return NewBackplaneSupervisorDriver(), nil
	default:
		return nil, fmt.Errorf("unknown backplane driver %q", driver)
	}
}

// GetAPIServerDriver returns an apiserver driver by name.
func GetAPIServerDriver(driver DriverMode) (Driver, error) {
	switch driver {
	case DockerMode:
		return NewAPIServerDockerDriver(), nil
	case SupervisorMode:
		return NewAPIServerSupervisorDriver(), nil
	default:
		return nil, fmt.Errorf("unknown apiserver driver %q", driver)
	}
}

// GetTunnelProxyDriver returns a tunnel proxy driver by name.
func GetTunnelProxyDriver(driver DriverMode) (Driver, error) {
	switch driver {
	case DockerMode:
		return NewTunnelProxyDockerDriver(), nil
	case SupervisorMode:
		return NewTunnelProxySupervisorDriver(), nil
	default:
		return nil, fmt.Errorf("unknown tunnel proxy driver %q", driver)
	}
}
