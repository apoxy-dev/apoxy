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
	workerdManagerContainerNamePrefix = "apoxy-workerd-manager-"
	workerdManagerImageRepo           = "workerd-manager"
	// workerdSocketMountPath is where the shared resident-socket volume mounts in
	// both the manager and the backplane. The manager's runtime dirs (state/root/
	// images/control socket) default under here, and the resident's host inbound
	// UDS the backplane's Envoy dials lands here too.
	workerdSocketMountPath = "/run/workerd-manager"
)

// WorkerdManagerDockerDriver runs the APO-796 workerd-manager: a privileged,
// gVisor-capable sidecar that hosts the one shared resident workerd. It joins the
// apiserver's network namespace (so its kube-API and routing-publish traffic
// reach the apiserver over loopback, with no relaxation of the publish channel's
// loopback-only guard) and shares a volume with the backplane carrying the
// resident's host UDS.
type WorkerdManagerDockerDriver struct {
	dockerDriverBase
}

// NewWorkerdManagerDockerDriver creates a new Docker driver for workerd-manager.
func NewWorkerdManagerDockerDriver() *WorkerdManagerDockerDriver {
	return &WorkerdManagerDockerDriver{}
}

// Start implements the Driver interface.
func (d *WorkerdManagerDockerDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	serviceName string,
	opts ...Option,
) (string, error) {
	setOpts := DefaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}
	if setOpts.NetworkContainer == "" {
		return "", fmt.Errorf("workerd-manager driver requires WithNetworkContainer (the apiserver container)")
	}

	if err := d.Init(ctx, opts...); err != nil {
		return "", err
	}

	imageRef := d.ImageRef(workerdManagerImageRepo)
	cname, found, err := dockerutils.Collect(
		ctx,
		workerdManagerContainerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.workerd_manager", serviceName),
	)
	if err != nil {
		return "", err
	} else if found {
		log.Infof("Container %s already running", cname)
		return cname, nil
	}

	if err := exec.CommandContext(ctx, "docker", "image", "inspect", imageRef).Run(); err != nil {
		if err := exec.CommandContext(ctx, "docker", "pull", imageRef).Run(); err != nil {
			return "", fmt.Errorf("failed to pull image %s: %w", imageRef, err)
		}
	}

	log.Infof("Starting container %s", cname)

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--pull="+d.PullPolicy(),
		"--detach",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--label", "org.apoxy.workerd_manager="+serviceName,
		// gVisor/runsc needs the broad privileges the backplane also takes.
		"--privileged",
		// Share the apiserver's network namespace so the manager reaches the kube
		// API (localhost:8443) and the routing publish channel (127.0.0.1:2021) over
		// loopback. This keeps the publish receiver loopback-only.
		"--network", "container:"+setOpts.NetworkContainer,
	)
	if setOpts.WorkerdSocketVolume != "" {
		cmd.Args = append(cmd.Args, "-v", setOpts.WorkerdSocketVolume+":"+workerdSocketMountPath)
	}

	cmd.Args = append(cmd.Args, imageRef)
	cmd.Args = append(cmd.Args, []string{
		"--project_id=" + orgID.String(),
		// Dev kube-auth: an insecure rest.Config to the apiserver over the shared
		// loopback (see cmd/workerd-manager dev mode).
		"--dev=true",
		// The apiserver's loopback publish channel (apiserver --workerd_publish_addr).
		"--backplane_publish_addr=127.0.0.1:2021",
	}...)
	cmd.Args = append(cmd.Args, setOpts.Args...)

	log.Debugf("Running command: %v", cmd.String())

	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start workerd-manager: %s", execErr.Stderr)
		}
		return "", fmt.Errorf("failed to start workerd-manager: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return "", fmt.Errorf("failed to start workerd-manager: %w", err)
	}

	return cname, nil
}

// Stop implements the Driver interface.
func (d *WorkerdManagerDockerDriver) Stop(orgID uuid.UUID, serviceName string) {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	cname, found, err := dockerutils.Collect(
		ctx,
		workerdManagerContainerNamePrefix,
		d.ImageRef(workerdManagerImageRepo),
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.workerd_manager", serviceName),
	)
	if err != nil {
		log.Errorf("Error stopping Docker container: %v", err)
	} else if !found {
		log.Infof("Container %s wasn't found running", cname)
		return
	}
	log.Infof("Stopping container %s", cname)
	if err := exec.CommandContext(ctx, "docker", "rm", "-f", cname).Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			log.Errorf("failed to stop workerd-manager: %s", execErr.Stderr)
		} else {
			log.Errorf("failed to stop workerd-manager: %v", err)
		}
	}
}

// GetAddr implements the Driver interface.
func (d *WorkerdManagerDockerDriver) GetAddr(ctx context.Context) (string, error) {
	cname, found, err := dockerutils.Collect(
		ctx,
		workerdManagerContainerNamePrefix,
		d.ImageRef(workerdManagerImageRepo),
	)
	if err != nil {
		return "", err
	} else if !found {
		return "", fmt.Errorf("workerd-manager not found")
	}
	return cname, nil
}
