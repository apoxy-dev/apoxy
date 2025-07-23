package drivers

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy/build"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
	dockerutils "github.com/apoxy-dev/apoxy/pkg/utils/docker"
)

const (
	tunnelProxyContainerNamePrefix = "apoxy-tunnelproxy-"
	tunnelProxyImageRepo           = "tunnelproxy"
)

// TunnelProxyDockerDriver implements the Driver interface for Docker.
type TunnelProxyDockerDriver struct {
	dockerDriverBase
}

// NewTunnelProxyDockerDriver creates a new Docker driver for tunnelproxy.
func NewTunnelProxyDockerDriver() *TunnelProxyDockerDriver {
	return &TunnelProxyDockerDriver{}
}

// Start implements the Driver interface.
func (d *TunnelProxyDockerDriver) Start(
	ctx context.Context,
	projectID uuid.UUID,
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

	imageRef := d.ImageRef(tunnelProxyImageRepo)
	cname, found, err := dockerutils.Collect(
		ctx,
		tunnelProxyContainerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", projectID.String()),
		dockerutils.WithLabel("org.apoxy.tunnelproxy", proxyName),
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

	certsDir := filepath.Join(os.TempDir(), "apoxy-certs")

	log.Infof("Generating self-signed certificates at %s and %s",
		filepath.Join(certsDir, "tunnelproxy.crt"),
		filepath.Join(certsDir, "tunnelproxy.key"))

	_, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	if err != nil {
		return "", fmt.Errorf("failed to generate self-signed certificates: %w", err)
	}

	if err := cryptoutils.SaveCertificatePEM(serverCert, certsDir, "tunnelproxy", false); err != nil {
		return "", fmt.Errorf("failed to save CA certificate: %w", err)
	}

	log.Infof("Starting container %s", cname)

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--pull="+d.PullPolicy(),
		"--detach",
		"--name", cname,
		"--label", "org.apoxy.project_id="+projectID.String(),
		"--label", "org.apoxy.tunnelproxy="+proxyName,
		"--privileged",
		"--network", dockerutils.NetworkName,
		"--volume", fmt.Sprintf("%s:/etc/apoxy/certs", certsDir),
		"-p", "9443:9443/udp",
	)

	apiserverAddr := setOpts.APIServerAddr
	if apiserverAddr == "" {
		apiServerHost, err := getDockerBridgeIP()
		if err != nil {
			return "", fmt.Errorf("failed to get docker bridge IP: %w", err)
		}
		apiserverAddr = fmt.Sprintf("%s:8443", apiServerHost)
	}
	apiserverHost, _, err := net.SplitHostPort(apiserverAddr)
	if err != nil {
		return "", fmt.Errorf("failed to split host and port from apiserver address: %w", err)
	}

	cmd.Args = append(cmd.Args, imageRef)
	cmd.Args = append(cmd.Args, []string{
		"--apiserver_addr=" + apiserverAddr,
		fmt.Sprintf("--jwks_urls=http://%s:%d%s", apiserverHost, 8444, token.JWKSURI),
		"--network_id=" + projectID.String()[len(projectID.String())-6:],
		"--cksum_recalc=true",
	}...)
	if build.IsDev() {
		cmd.Args = append(cmd.Args, "--dev")
	}
	cmd.Args = append(cmd.Args, setOpts.Args...)

	log.Debugf("Running command: %v", cmd.String())

	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start tunnel proxy: %s", execErr.Stderr)
		}
		return "", fmt.Errorf("failed to start tunnel proxy: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return "", fmt.Errorf("failed to start tunnel proxy: %w", err)
	}

	return cname, nil
}

// Stop implements the Driver interface.
func (d *TunnelProxyDockerDriver) Stop(orgID uuid.UUID, proxyName string) {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	cname, found, err := dockerutils.Collect(
		ctx,
		tunnelProxyContainerNamePrefix,
		d.ImageRef(tunnelProxyImageRepo),
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.tunnelproxy", proxyName),
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
			log.Errorf("failed to stop tunnel proxy: %s", execErr.Stderr)
		} else {
			log.Errorf("failed to stop tunnel proxy: %v", err)
		}
	}
}

// GetAddr implements the Driver interface.
func (d *TunnelProxyDockerDriver) GetAddr(ctx context.Context) (string, error) {
	cname, found, err := dockerutils.Collect(
		ctx,
		tunnelProxyContainerNamePrefix,
		d.ImageRef(tunnelProxyImageRepo),
	)
	if err != nil {
		return "", err
	} else if !found {
		return "", fmt.Errorf("tunnel proxy not found")
	}
	return cname, nil
}
