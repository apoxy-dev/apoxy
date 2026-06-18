package drivers

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/pkg/log"
	dockerutils "github.com/apoxy-dev/apoxy/pkg/utils/docker"
)

const (
	backplaneContainerNamePrefix = "apoxy-backplane-"
	backplaneImageRepo           = "backplane"
)

// BackplaneDockerDriver implements the Driver interface for Docker.
type BackplaneDockerDriver struct {
	dockerDriverBase
}

// NewBackplaneDockerDriver creates a new Docker driver for backplane.
func NewBackplaneDockerDriver() *BackplaneDockerDriver {
	return &BackplaneDockerDriver{}
}

// Start implements the Driver interface.
func (d *BackplaneDockerDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	proxyName string,
	opts ...Option,
) (string, error) {
	setOpts := DefaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}

	if err := d.Init(ctx, opts...); err != nil {
		return "", err
	}

	imageRef := d.ImageRef(backplaneImageRepo)
	cname, found, err := dockerutils.Collect(
		ctx,
		backplaneContainerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.backplane", proxyName),
	)
	if err != nil {
		return "", err
	} else if found {
		log.Infof("Container %s already running", cname)
		return cname, nil
	}

	// Check if we have the image.
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", imageRef).Run(); err != nil {
		// If not, pull it.
		if err := exec.CommandContext(ctx, "docker", "pull", imageRef).Run(); err != nil {
			return "", fmt.Errorf("failed to pull image %s: %w", imageRef, err)
		}
	}

	log.Infof("Starting container %s", cname)

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--pull="+d.PullPolicy(),
		"--detach",
		//"--rm",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--label", "org.apoxy.backplane="+proxyName,
		"--privileged",
		"--network", dockerutils.NetworkName,
	)
	// APO-796: share the resident-socket volume so Envoy can dial the workerd
	// resident's host UDS that the co-located workerd-manager surfaces there.
	if setOpts.WorkerdSocketVolume != "" {
		cmd.Args = append(cmd.Args, "-v", setOpts.WorkerdSocketVolume+":"+workerdSocketMountPath)
	}

	apiserverAddr := setOpts.APIServerAddr
	if apiserverAddr == "" {
		apiServerHost, err := getDockerBridgeIP()
		if err != nil {
			return "", fmt.Errorf("failed to get docker bridge IP: %w", err)
		}
		apiserverAddr = fmt.Sprintf("%s:8443", apiServerHost)
	}

	cmd.Args = append(cmd.Args, imageRef)
	cmd.Args = append(cmd.Args, []string{
		"--project_id=" + orgID.String(),
		// Use the same name for both proxy and replica - we only have one replica.
		"--proxy=" + proxyName,
		"--replica=" + proxyName,
		"--apiserver_addr=" + apiserverAddr,
		"--use_envoy_contrib=true",
	}...)
	cmd.Args = append(cmd.Args, setOpts.Args...)

	log.Debugf("Running command: %v", cmd.String())

	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start Envoy backplane: %s", execErr.Stderr)
		}
		return "", fmt.Errorf("failed to start Envoy backplane: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return "", fmt.Errorf("failed to start Envoy backplane: %w", err)
	}

	return cname, nil
}

// Stop implements the Driver interface.
func (d *BackplaneDockerDriver) Stop(orgID uuid.UUID, proxyName string) {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	cname, found, err := dockerutils.Collect(
		ctx,
		backplaneContainerNamePrefix,
		d.ImageRef(backplaneImageRepo),
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.backplane", proxyName),
	)
	if err != nil {
		log.Errorf("Error stopping Docker container: %v", err)
	} else if !found {
		log.Infof("Container %s wasn't found running", cname)
		return
	}
	log.Infof("Stopping container %s", cname)
	cmd := exec.CommandContext(ctx,
		"docker", "rm", "-f", cname,
	)
	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			log.Errorf("failed to stop Envoy backplane: %s", execErr.Stderr)
		} else {
			log.Errorf("failed to stop Envoy backplane: %v", err)
		}
	}
}

// GetAddr implements the Driver interface.
func (d *BackplaneDockerDriver) GetAddr(ctx context.Context) (string, error) {
	cname, found, err := dockerutils.Collect(
		ctx,
		backplaneContainerNamePrefix,
		d.ImageRef(backplaneImageRepo),
	)
	if err != nil {
		return "", err
	} else if !found {
		return "", fmt.Errorf("backplane not found")
	}
	return cname, nil
}
