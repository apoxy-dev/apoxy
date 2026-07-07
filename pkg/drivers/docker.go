package drivers

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/apoxy-dev/apoxy/build"
	dockerutils "github.com/apoxy-dev/apoxy/pkg/utils/docker"
)

// imageRegistry is the public Artifact Registry repo Apoxy's images are pulled
// from (anonymous-pullable). Replaces the former docker.io/apoxy namespace.
// Keep in sync with ci's PublicGARRepo (the publish target).
const imageRegistry = "us-west1-docker.pkg.dev/apoxy-dev/public"

// dockerDriverBase is a wrapper for the Docker driver containing
// common functionality.
type dockerDriverBase struct {
	d Driver
}

// Init initializes the Docker driver.
func (db *dockerDriverBase) Init(
	ctx context.Context,
	opts ...Option,
) error {
	// Check for network and create if not exists.
	err := exec.CommandContext(
		ctx,
		"docker",
		"network",
		"inspect",
		dockerutils.NetworkName,
	).Run()
	if err != nil {
		createErr := exec.CommandContext(
			ctx,
			"docker",
			"network",
			"create",
			"--ipv6",
			dockerutils.NetworkName,
		).Run()
		if createErr != nil {
			return fmt.Errorf("failed to create network apoxy: %w", createErr)
		}
	}

	return nil
}

func (db *dockerDriverBase) ImageRef(repo string) string {
	imgTag := build.BuildVersion
	if build.IsDev() {
		imgTag = "latest"
	}
	return fmt.Sprintf("%s/%s:%s", imageRegistry, repo, imgTag)
}

func (db *dockerDriverBase) PullPolicy() string {
	pullPolicy := "missing"
	if build.IsDev() {
		pullPolicy = "always"
	}
	return pullPolicy
}
