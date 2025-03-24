// A generated module for ApoxyCli functions
//
// This module has been generated via dagger init and serves as a reference to
// basic module structure as you get started with Dagger.
//
// Two functions have been pre-created. You can modify, delete, or add to them,
// as needed. They demonstrate usage of arguments and return types using simple
// echo and grep commands. The functions can be called from the dagger CLI or
// from one of the SDKs.
//
// The first line in this comment block is a short description line and the
// rest is a long description with more detail on the module's purpose or usage,
// if appropriate. All modules should have a short description.

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/containerd/platforms"

	"dagger/apoxy-cli/internal/dagger"
)

// Note that 0.12.0 and later fail to cross compile for Darwin.
// See https://github.com/ziglang/zig/issues/20689
const ZigVersion = "0.11.0"

type ApoxyCli struct{}

func canonArchFromGoArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return goarch
	}
}

func hostArch() string {
	return canonArchFromGoArch(runtime.GOARCH)
}

// This wrapper script pretends to be Gold linker (see issue link bellow).
// TODO(dilyevsky): When Go team finally gets around fixing their
// https://github.com/golang/go/issues/22040 hack, we can undo this hack.
var zigWrapperScript = `#!/bin/sh

# Find the real zig executable
REAL_ZIG=$(which -a zig | grep -v "$0" | head -1)

# Check if the command contains both required arguments
case "$*" in
    *-fuse-ld=gold*-Wl,--version* | *-Wl,--version*-fuse-ld=gold*)
        echo "GNU gold"
        exit 0
        ;;
    *)
        # Forward all other commands to the real zig
        exec "$REAL_ZIG" "$@"
        ;;
esac
`

// BuilderContainer builds a CLI binary.
func (m *ApoxyCli) BuilderContainer(ctx context.Context, src *dagger.Directory) *dagger.Container {
	return dag.Container().
		From("golang:1.23-bookworm").
		WithWorkdir("/").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("go-build")).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		// Install Zig toolchain.
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{
			"apt-get", "install", "-yq", "xz-utils", "clang",
		}).
		WithExec([]string{
			"wget", fmt.Sprintf("https://ziglang.org/download/%s/zig-linux-%s-%s.tar.xz", ZigVersion, hostArch(), ZigVersion),
		}).
		WithExec([]string{
			"tar", "-xf", fmt.Sprintf("zig-linux-%s-%s.tar.xz", hostArch(), ZigVersion),
		}).
		WithExec([]string{
			"ln", "-s", fmt.Sprintf("/zig-linux-%s-%s/zig", hostArch(), ZigVersion), "/bin/zig",
		}).
		WithNewFile("/bin/zig-wrapper", zigWrapperScript, dagger.ContainerWithNewFileOpts{
			Permissions: 0755,
		}).
		WithDirectory("/src", src,
			dagger.ContainerWithDirectoryOpts{
				Exclude: []string{"secrets/**"}, // exclude secrets from build context
			}).
		WithWorkdir("/src")
}

// BuildCLI builds a CLI binary.
func (m *ApoxyCli) BuildCLI(
	ctx context.Context,
	src *dagger.Directory,
	platform, tag, sha string,
) *dagger.Container {
	p := dagger.Platform(platform)
	goarch := archOf(p)
	os := osOf(p)

	pkg := "github.com/apoxy-dev/apoxy-cli"
	date := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", time.Now().Year(), time.Now().Month(), time.Now().Day(), time.Now().Hour(), time.Now().Minute(), time.Now().Second())
	ldFlags := []string{
		fmt.Sprintf("-X '%s/build.BuildVersion=%s'", pkg, tag),
		fmt.Sprintf("-X '%s/build.BuildDate=%s'", pkg, date),
		fmt.Sprintf("-X '%s/build.CommitHash=%s'", pkg, sha),
		"-w", // disable DWARF
		// Before you think about adding -s here, see https://github.com/ziglang/zig/issues/22844
	}

	targetArch := canonArchFromGoArch(goarch)
	zigTarget := fmt.Sprintf("%s-linux-musl", targetArch)
	if os == "darwin" {
		zigTarget = fmt.Sprintf("%s-macos", targetArch)
	}

	builder := m.BuilderContainer(ctx, src)

	if os == "darwin" {
		builder = builder.
			WithExec([]string{"apt-get", "update"}).
			WithExec([]string{"apt-get", "install", "-yq", "gcc", "g++", "zlib1g-dev", "libmpc-dev", "libmpfr-dev", "libgmp-dev"}).
			WithExec([]string{
				"wget", fmt.Sprintf("https://apoxy-public-build-tools.s3.us-west-2.amazonaws.com/MacOSX14.sdk.tar.xz"),
			}).
			WithExec([]string{
				"tar", "-xf", "MacOSX14.sdk.tar.xz",
			}).
			WithExec([]string{
				"mv", "MacOSX14.sdk", "/macsdk",
			})
	}

	return builder.
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", os).
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", fmt.Sprintf("zig-wrapper cc --target=%s --sysroot=/macsdk -I/macsdk/usr/include -L/macsdk/usr/lib -F/macsdk/System/Library/Frameworks -Wno-expansion-to-defined -Wno-availability -Wno-nullability-completeness -DZIG_STATIC_ZLIB=on", zigTarget)).
		WithEnvVariable("CXX", fmt.Sprintf("zig-wrapper c++ --target=%s --sysroot=/macsdk -I/macsdk/usr/include -L/macsdk/usr/lib -F/macsdk/System/Library/Frameworks -Wno-expansion-to-defined -Wno-availability -Wno-nullability-completeness -DZIG_STATIC_ZLIB=on", zigTarget)).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod-"+goarch)).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("go-build-"+goarch)).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithExec([]string{"go", "build", "-o", "/apoxy", "-ldflags", strings.Join(ldFlags, " "), "-tags", "netgo", "."})
}

// PublishGithubRelease publishes a CLI binary to GitHub releases.
func (m *ApoxyCli) PublishGithubRelease(
	ctx context.Context,
	src *dagger.Directory,
	githubToken *dagger.Secret,
	tag, sha string,
) *dagger.Container {
	cliCtrLinuxAmd64 := m.BuildCLI(ctx, src, "linux/amd64", tag, sha)
	cliCtrLinuxArm64 := m.BuildCLI(ctx, src, "linux/arm64", tag, sha)
	cliCtrMacosAmd64 := m.BuildCLI(ctx, src, "darwin/amd64", tag, sha)
	cliCtrMacosArm64 := m.BuildCLI(ctx, src, "darwin/arm64", tag, sha)

	return dag.Container().
		From("ubuntu:22.04").
		WithEnvVariable("DEBIAN_FRONTEND", "noninteractive").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "curl", "wget", "tar"}).
		WithExec([]string{"wget", "https://github.com/cli/cli/releases/download/v2.62.0/gh_2.62.0_linux_amd64.tar.gz"}).
		WithExec([]string{"tar", "xzf", "gh_2.62.0_linux_amd64.tar.gz"}).
		WithExec([]string{"mv", "gh_2.62.0_linux_amd64/bin/gh", "/usr/local/bin/gh"}).
		WithExec([]string{"rm", "-rf", "gh_2.62.0_linux_amd64", "gh_2.62.0_linux_amd64.tar.gz"}).
		WithSecretVariable("GITHUB_TOKEN", githubToken).
		WithFile("/apoxy-linux-amd64", cliCtrLinuxAmd64.File("/apoxy")).
		WithFile("/apoxy-linux-arm64", cliCtrLinuxArm64.File("/apoxy")).
		WithFile("/apoxy-darwin-amd64", cliCtrMacosAmd64.File("/apoxy")).
		WithFile("/apoxy-darwin-arm64", cliCtrMacosArm64.File("/apoxy")).
		WithExec([]string{
			"gh", "release", "create",
			tag,
			"--generate-notes",
			"--title", tag,
			"--repo", "github.com/apoxy-dev/apoxy-cli",
		}).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-linux-amd64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy-cli",
		}).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-linux-arm64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy-cli",
		}).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-darwin-amd64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy-cli",
		}).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-darwin-arm64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy-cli",
		})
}

func (m *ApoxyCli) BuildEdgeRuntime(
	ctx context.Context,
	platform string,
	// +optional
	src *dagger.Directory,
) *dagger.Container {
	if src == nil {
		src = dag.Git("https://github.com/supabase/edge-runtime").
			Tag("v1.62.2").
			Tree()
	}
	p := dagger.Platform(platform)
	return dag.Container(dagger.ContainerOpts{Platform: p}).
		From("rust:1.82.0-bookworm").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "llvm-dev", "libclang-dev", "gcc", "cmake", "binutils"}).
		WithWorkdir("/src").
		WithDirectory("/src", src).
		WithExec([]string{"cargo", "build", "--release"})
}

// PullEdgeRuntime pulls the edge runtime image from dockerhub.
func (m *ApoxyCli) PullEdgeRuntime(
	ctx context.Context,
	platform string,
) *dagger.Container {
	p := dagger.Platform(platform)
	return dag.Container(dagger.ContainerOpts{Platform: p}).
		From("docker.io/supabase/edge-runtime:v1.62.2")
}

// BuildAPIServer builds an API server binary.
func (m *ApoxyCli) BuildAPIServer(
	ctx context.Context,
	src *dagger.Directory,
) *dagger.Container {
	platform := dagger.Platform("linux/amd64")
	goarch := "amd64"
	targetArch := "x86_64"
	builder := m.BuilderContainer(ctx, src).
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", "linux").
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", fmt.Sprintf("zig-wrapper cc --target=%s-linux-musl", targetArch)).
		WithExec([]string{"go", "build", "-o", "apiserver", "./cmd/apiserver"})

	runtimeCtr := m.PullEdgeRuntime(ctx, string(platform))

	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithFile("/bin/apiserver", builder.File("/src/apiserver")).
		WithFile("/bin/edge-runtime", runtimeCtr.File("/usr/local/bin/edge-runtime")).
		WithEntrypoint([]string{"/bin/apiserver"})
}

func archOf(p dagger.Platform) string {
	return platforms.MustParse(string(p)).Architecture
}

func osOf(p dagger.Platform) string {
	return platforms.MustParse(string(p)).OS
}

// BuildBackplane builds a backplane binary.
func (m *ApoxyCli) BuildBackplane(
	ctx context.Context,
	src *dagger.Directory,
	platform string,
) *dagger.Container {
	p := dagger.Platform(platform)
	goarch := archOf(p)

	bpOut := filepath.Join("build", "backplane-"+goarch)
	dsOut := filepath.Join("build", "dial-stdio-"+goarch)
	otelOut := filepath.Join("build", "otel-collector-"+goarch)

	builder := m.BuilderContainer(ctx, src).
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", "linux").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod-"+goarch)).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("go-build-"+goarch)).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", fmt.Sprintf("zig-wrapper cc --target=%s-linux-musl", canonArchFromGoArch(goarch))).
		WithExec([]string{"go", "build", "-ldflags", "-v -linkmode=external", "-o", bpOut, "./cmd/backplane"}).
		WithExec([]string{"go", "build", "-ldflags", "-v -linkmode=external", "-o", dsOut, "./cmd/dial-stdio"}).
		WithExec([]string{"wget", "https://github.com/apoxy-dev/otel-collector/archive/refs/tags/v1.0.0.tar.gz"}).
		WithExec([]string{"tar", "-xvf", "v1.0.0.tar.gz"}).
		WithExec([]string{"mkdir", "-p", "/src/github.com/apoxy-dev"}).
		WithExec([]string{"mv", "otel-collector-1.0.0", "/src/github.com/apoxy-dev/otel-collector"}).
		WithWorkdir("/src/github.com/apoxy-dev/otel-collector/otelcol-apoxy").
		WithExec([]string{"go", "build", "-o", otelOut})

	runtimeCtr := m.PullEdgeRuntime(ctx, platform)

	return dag.Container(dagger.ContainerOpts{Platform: p}).
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithExec([]string{"apk", "add", "-u", "iptables", "iproute2", "net-tools"}).
		WithFile("/bin/backplane", builder.File(bpOut)).
		WithFile("/bin/dial-stdio", builder.File(dsOut)).
		WithFile("/bin/edge-runtime", runtimeCtr.File("/usr/local/bin/edge-runtime")).
		WithExec([]string{
			"/bin/backplane",
			"--project_id=apoxy",
			"--proxy=apoxy",
			"--replica=apoxy",
			"--apiserver_addr=localhost:8443",
			"--use_envoy_contrib=true",
			"--download_envoy_only=true",
		}).
		WithEntrypoint([]string{"/bin/backplane"})
}

// PublishImages publishes images to the registry.
func (m *ApoxyCli) PublishImages(
	ctx context.Context,
	src *dagger.Directory,
	registryPassword *dagger.Secret,
	tag string,
) error {
	aCtr := m.BuildAPIServer(ctx, src)
	addr, err := aCtr.
		WithRegistryAuth(
			"registry-1.docker.io",
			"apoxy",
			registryPassword,
		).
		Publish(ctx, "docker.io/apoxy/apiserver:"+tag)
	if err != nil {
		return err
	}

	fmt.Println("API server image published to", addr)

	var bCtrs []*dagger.Container
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		bCtr := m.BuildBackplane(ctx, src, platform)
		bCtrs = append(bCtrs, bCtr)
	}

	addr, err = dag.Container().
		WithRegistryAuth(
			"registry-1.docker.io",
			"apoxy",
			registryPassword,
		).
		Publish(ctx, "docker.io/apoxy/backplane:"+tag, dagger.ContainerPublishOpts{
			PlatformVariants: bCtrs,
		})
	if err != nil {
		return err
	}

	fmt.Println("Backplane images published to", addr)

	return nil
}

// PublishHelmRelease publishes a Helm release.
func (m *ApoxyCli) PublishHelmRelease(
	ctx context.Context,
	src *dagger.Directory,
	registryPassword *dagger.Secret,
	tag string,
) (string, error) {
	return dag.Container().
		From("cgr.dev/chainguard/helm:latest-dev").
		WithDirectory("/src", src).
		WithWorkdir("/src").
		WithSecretVariable("REGISTRY_PASSWORD", registryPassword).
		WithExec([]string{
			"sh", "-c", `echo $REGISTRY_PASSWORD | helm registry login registry-1.docker.io -u apoxy --password-stdin`,
		}).
		WithExec([]string{
			"helm", "package",
			"--version", tag,
			"--app-version", tag,
			"--destination", "/tmp",
			"apoxy-gateway",
		}).
		WithExec([]string{
			"helm", "push",
			fmt.Sprintf("/tmp/apoxy-gateway-%s.tgz", tag),
			"oci://registry-1.docker.io/apoxy",
		}).
		Stdout(ctx)
}
