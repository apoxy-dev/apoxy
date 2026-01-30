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

	"github.com/containerd/platforms"

	"dagger/apoxy-cli/internal/dagger"
)

const ZigVersion = "0.14.1"

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

// BuilderContainer builds a containers for compiling go binaries.
func (m *ApoxyCli) BuilderContainer(ctx context.Context, src *dagger.Directory) *dagger.Container {
	return dag.Container().
		From("golang:1.24-bookworm").
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
			"wget", fmt.Sprintf("https://ziglang.org/download/%s/zig-%s-linux-%s.tar.xz", ZigVersion, hostArch(), ZigVersion),
		}).
		WithExec([]string{
			"tar", "-xf", fmt.Sprintf("zig-%s-linux-%s.tar.xz", hostArch(), ZigVersion),
		}).
		WithExec([]string{
			"ln", "-s", fmt.Sprintf("/zig-%s-linux-%s/zig", hostArch(), ZigVersion), "/bin/zig",
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

// DarwinBuilderContainer creates a container for building on macOS.
func (m *ApoxyCli) DarwinBuilderContainer(ctx context.Context, src *dagger.Directory) *dagger.Container {
	return m.BuilderContainer(ctx, src).
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

// PublishBuilderContainer publishes a container for compiling go binaries.
func (m *ApoxyCli) PublishBuilderContainer(
	ctx context.Context,
	src *dagger.Directory,
	registryPassword *dagger.Secret,
) error {
	_, err := m.BuilderContainer(ctx, src).
		WithRegistryAuth(
			"registry-1.docker.io",
			"apoxy",
			registryPassword,
		).
		Publish(ctx, "docker.io/apoxy/gobuilder:latest")
	return err
}

// BuildCLI builds a CLI binary.
func (m *ApoxyCli) BuildCLI(
	ctx context.Context,
	src *dagger.Directory,
	// +optional
	platform string,
	// +optional
	tag string,
	// +optional
	sha string,
) *dagger.Container {
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	if tag == "" {
		tag = "latest"
	}
	if sha == "" {
		sha = "unknown"
	}
	p := dagger.Platform(platform)
	goarch := archOf(p)
	os := osOf(p)

	pkg := "github.com/apoxy-dev/apoxy"
	ldFlags := []string{
		fmt.Sprintf("-X '%s/build.BuildVersion=%s'", pkg, tag),
		fmt.Sprintf("-X '%s/build.BuildDate=%s'", pkg, time.Now().Format("2006-01-02T15:04:05Z")),
		fmt.Sprintf("-X '%s/build.CommitHash=%s'", pkg, sha),
		"-w", // disable DWARF
		// Before you think about adding -s here, see https://github.com/ziglang/zig/issues/22844
	}

	targetArch := canonArchFromGoArch(goarch)
	zigTarget := fmt.Sprintf("%s-linux-musl", targetArch)
	var builder *dagger.Container

	if os == "darwin" {
		zigTarget = fmt.Sprintf("%s-macos", targetArch)
		builder = m.DarwinBuilderContainer(ctx, src)
	} else {
		builder = m.BuilderContainer(ctx, src)
	}

	return builder.
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", os).
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", strings.Join([]string{
			"zig-wrapper cc",
			"--target=" + zigTarget,
			//"--sysroot=/macsdk",
			"-I/macsdk/usr/include",
			"-L/macsdk/usr/lib",
			"-F/macsdk/System/Library/Frameworks",
			"-Wno-expansion-to-defined",
			"-Wno-availability",
			"-Wno-nullability-completeness",
			"-Wno-macro-redefined",
			"-Wno-typedef-redefinition",
			"-DZIG_STATIC_ZLIB=on",
		}, " ")).
		WithEnvVariable("CXX", strings.Join([]string{
			"zig-wrapper c++",
			"--target=" + zigTarget,
			//"--sysroot=/macsdk",
			"-I/macsdk/usr/include",
			"-L/macsdk/usr/lib",
			"-F/macsdk/System/Library/Frameworks",
			"-Wno-expansion-to-defined",
			"-Wno-availability",
			"-Wno-nullability-completeness",
			"-Wno-macro-redefined",
			"-Wno-typedef-redefinition",
			"-DZIG_STATIC_ZLIB=on",
		}, " ")).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod-"+goarch)).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("go-build-"+goarch)).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithExec([]string{"go", "build", "-o", "/apoxy", "-ldflags", strings.Join(ldFlags, " "), "-tags", "netgo", "."})
}

// BuildCLIRelease builds a CLI container for release.
func (m *ApoxyCli) BuildCLIRelease(
	ctx context.Context,
	src *dagger.Directory,
	platform string,
	tag, sha string,
) *dagger.Container {
	buildCtr := m.BuildCLI(ctx, src, platform, tag, sha)
	return dag.Container(dagger.ContainerOpts{Platform: dagger.Platform(platform)}).
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithExec([]string{"apk", "add", "-u", "iptables", "ip6tables", "iproute2", "net-tools", "sed", "coreutils"}).
		WithFile("/bin/apoxy", buildCtr.File("/apoxy")).
		WithEntrypoint([]string{"/bin/apoxy"})
}

// GenerateReleaseNotes uses an LLM to generate release notes from git commits.
func (m *ApoxyCli) GenerateReleaseNotes(
	ctx context.Context,
	src *dagger.Directory,
	newTag string,
) (string, error) {
	gitCtr := dag.Container().
		From("alpine/git:latest").
		WithDirectory("/src", src).
		WithWorkdir("/src")

	// Auto-detect previous tag (latest tag before newTag).
	previousTag, err := gitCtr.
		WithExec([]string{"git", "describe", "--tags", "--abbrev=0", newTag + "^"}).
		Stdout(ctx)
	if err != nil {
		// No previous tag found, use all commits.
		previousTag = ""
	}
	previousTag = strings.TrimSpace(previousTag)

	var logCmd []string
	if previousTag != "" {
		logCmd = []string{"git", "log", fmt.Sprintf("%s..HEAD", previousTag), "--oneline"}
	} else {
		logCmd = []string{"git", "log", "--oneline", "-50"} // Last 50 commits if no tag
	}

	commitLog, err := gitCtr.WithExec(logCmd).Stdout(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get git log: %w", err)
	}

	prompt := fmt.Sprintf(`Generate release notes for version %s based on these git commits.

Instructions:
- Group changes by category: Features, Bug Fixes, Improvements, Infrastructure
- Be concise but informative
- Use markdown formatting with ## headers for categories
- Each item should be a bullet point with a descriptive title, optionally grouping related commits
- After each title, include commit link(s) in the format: ([hash](https://github.com/apoxy-dev/apoxy/commit/<hash>))
- For grouped items with multiple commits, list all links: ([hash1](url1), [hash2](url2))
- Extract commit hashes from the beginning of each commit line
- Focus on user-facing changes, skip minor refactors
- Previous version: %s

Commits:
%s`, newTag, previousTag, commitLog)

	result, err := dag.LLM().
		WithPrompt(prompt).
		LastReply(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to generate release notes: %w", err)
	}

	return result, nil
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

	// Generate release notes using LLM (auto-detects previous tag).
	releaseNotes, err := m.GenerateReleaseNotes(ctx, src, tag)

	// Build release command with fallback.
	var releaseCmd []string
	if err != nil || releaseNotes == "" {
		// Fallback to GitHub's auto-generated notes.
		fmt.Println("LLM release notes failed, using GitHub generated notes:", err)
		releaseCmd = []string{
			"gh", "release", "create",
			tag,
			"--generate-notes",
			"--title", tag,
			"--repo", "github.com/apoxy-dev/apoxy",
		}
	} else {
		releaseCmd = []string{
			"gh", "release", "create",
			tag,
			"--notes", releaseNotes,
			"--title", tag,
			"--repo", "github.com/apoxy-dev/apoxy",
		}
	}

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
		WithExec(releaseCmd).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-linux-amd64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy",
		}).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-linux-arm64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy",
		}).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-darwin-amd64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy",
		}).
		WithExec([]string{
			"gh", "release", "upload",
			tag,
			"/apoxy-darwin-arm64",
			"--clobber",
			"--repo", "github.com/apoxy-dev/apoxy",
		})
}

// EdgeRuntimeVersion is the version of the Apoxy edge-runtime fork.
const EdgeRuntimeVersion = "v0.1.0"

func (m *ApoxyCli) BuildEdgeRuntime(
	ctx context.Context,
	platform string,
	// +optional
	src *dagger.Directory,
	// +optional
	sccacheToken *dagger.Secret,
) *dagger.Container {
	if src == nil {
		src = dag.Git("https://github.com/apoxy-dev/edge-runtime").
			Branch("main").
			Tree()
	}
	p := dagger.Platform(platform)
	goarch := archOf(p)
	targetArch := canonArchFromGoArch(goarch)

	builder := dag.Container(dagger.ContainerOpts{Platform: p}).
		From("rust:1.82.0-bookworm").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "llvm-dev", "libclang-dev", "gcc", "cmake", "binutils", "clang", "mold", "curl"}).
		// Install sccache for compilation caching (0.11.0 is compatible with rustc 1.82.0).
		WithExec([]string{"sh", "-c", "curl -fsSL https://github.com/mozilla/sccache/releases/download/v0.11.0/sccache-v0.11.0-$(uname -m)-unknown-linux-musl.tar.gz | tar xzf - -C /usr/local/bin --strip-components=1 --wildcards '*/sccache'"}).
		WithEnvVariable("SCCACHE_WEBDAV_ENDPOINT", "https://cache.depot.dev").
		WithEnvVariable("RUSTC_WRAPPER", "/usr/local/bin/sccache").
		// Configure mold as linker for faster linking.
		WithEnvVariable("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "clang").
		WithEnvVariable("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "-C link-arg=-fuse-ld=mold").
		WithEnvVariable("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", "clang").
		WithEnvVariable("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "-C link-arg=-fuse-ld=mold").
		WithMountedCache("/usr/local/cargo/registry", dag.CacheVolume("cargo-registry-"+goarch)).
		WithMountedCache("/src/target", dag.CacheVolume("cargo-target-"+goarch)).
		WithMountedCache("/root/.cache/sccache", dag.CacheVolume("sccache-"+targetArch)).
		WithWorkdir("/src").
		WithDirectory("/src", src)

	if sccacheToken != nil {
		builder = builder.WithSecretVariable("SCCACHE_WEBDAV_TOKEN", sccacheToken)
	}

	return builder.WithExec([]string{"cargo", "build", "--release"})
}

// PullEdgeRuntime builds the Apoxy edge-runtime fork from source.
// The built container includes the edge-runtime binary and main service.
func (m *ApoxyCli) PullEdgeRuntime(
	ctx context.Context,
	// +default=linux/arm64
	platform dagger.Platform,
	// +optional
	apoxyCliSrc *dagger.Directory,
	// +optional
	sccacheToken *dagger.Secret,
) *dagger.Container {
	goarch := archOf(platform)
	targetArch := canonArchFromGoArch(goarch)

	// Build edge-runtime from source.
	edgeRuntimeSrc := dag.Git("https://github.com/apoxy-dev/edge-runtime").
		Branch("main").
		Tree()

	builder := dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("rust:1.82.0-bookworm").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "llvm-dev", "libclang-dev", "gcc", "cmake", "binutils", "clang", "mold", "curl"}).
		// Install sccache for compilation caching (0.11.0 is compatible with rustc 1.82.0).
		WithExec([]string{"sh", "-c", "curl -fsSL https://github.com/mozilla/sccache/releases/download/v0.11.0/sccache-v0.11.0-$(uname -m)-unknown-linux-musl.tar.gz | tar xzf - -C /usr/local/bin --strip-components=1 --wildcards '*/sccache'"}).
		WithEnvVariable("SCCACHE_WEBDAV_ENDPOINT", "https://cache.depot.dev").
		WithEnvVariable("RUSTC_WRAPPER", "/usr/local/bin/sccache").
		// Configure mold as linker for faster linking.
		WithEnvVariable("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "clang").
		WithEnvVariable("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "-C link-arg=-fuse-ld=mold").
		WithEnvVariable("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", "clang").
		WithEnvVariable("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "-C link-arg=-fuse-ld=mold").
		WithMountedCache("/usr/local/cargo/registry", dag.CacheVolume("cargo-registry-"+goarch)).
		WithMountedCache("/src/target", dag.CacheVolume("cargo-target-"+goarch)).
		WithMountedCache("/root/.cache/sccache", dag.CacheVolume("sccache-"+targetArch)).
		WithWorkdir("/src").
		WithDirectory("/src", edgeRuntimeSrc)

	if sccacheToken != nil {
		builder = builder.WithSecretVariable("SCCACHE_WEBDAV_TOKEN", sccacheToken)
	}

	builder = builder.
		WithExec([]string{"cargo", "build", "--release"}).
		WithExec([]string{"cp", "/src/target/release/edge-runtime", "/edge-runtime"})

	// Create a minimal container with the binary and main service.
	ctr := dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("debian:bookworm-slim").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "libssl-dev", "ca-certificates"}).
		WithExec([]string{"rm", "-rf", "/var/lib/apt/lists/*"}).
		WithFile("/usr/local/bin/edge-runtime", builder.File("/edge-runtime")).
		WithExec([]string{"mkdir", "-p", "/etc/main"})

	// Copy the main service from this repo.
	if apoxyCliSrc != nil {
		ctr = ctr.WithFile("/etc/main/index.ts", apoxyCliSrc.File("pkg/edgefunc/mainservice/main-service.ts"))
	}

	return ctr
}

// BuildAPIServer builds an API server binary.
func (m *ApoxyCli) BuildAPIServer(
	ctx context.Context,
	src *dagger.Directory,
	// +optional
	platform string,
	// +optional
	sccacheToken *dagger.Secret,
) *dagger.Container {
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	p := dagger.Platform(platform)
	goarch := archOf(p)

	builder := m.BuilderContainer(ctx, src).
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", "linux").
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", fmt.Sprintf("zig-wrapper cc --target=%s-linux-musl", canonArchFromGoArch(goarch))).
		WithExec([]string{"go", "build", "-o", "apiserver", "./cmd/apiserver"})

	runtimeCtr := m.PullEdgeRuntime(ctx, p, src, sccacheToken)

	return dag.Container(dagger.ContainerOpts{Platform: p}).
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithFile("/bin/apiserver", builder.File("/src/apiserver")).
		WithFile("/bin/edge-runtime", runtimeCtr.File("/usr/local/bin/edge-runtime")).
		WithDirectory("/etc/main", runtimeCtr.Directory("/etc/main")).
		WithEntrypoint([]string{"/bin/apiserver"})
}

func archOf(p dagger.Platform) string {
	return platforms.MustParse(string(p)).Architecture
}

func osOf(p dagger.Platform) string {
	return platforms.MustParse(string(p)).OS
}

// hostPlatform returns the host platform string (e.g., "linux/amd64").
func hostPlatform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// CraneContainer returns a container with crane installed and authenticated.
func (m *ApoxyCli) CraneContainer(ctx context.Context, registryPassword *dagger.Secret) *dagger.Container {
	cranePlatform := hostArch()
	if cranePlatform == "x86_64" {
		cranePlatform = "x86_64"
	} else if cranePlatform == "aarch64" {
		cranePlatform = "arm64"
	}

	return dag.Container().
		From("alpine:latest").
		WithExec([]string{"apk", "add", "--no-cache", "curl"}).
		WithExec([]string{
			"sh", "-c",
			fmt.Sprintf("curl -sL https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_%s.tar.gz | tar xzf - -C /usr/local/bin crane", cranePlatform),
		}).
		WithSecretVariable("REGISTRY_PASSWORD", registryPassword).
		WithExec([]string{
			"sh", "-c",
			`echo $REGISTRY_PASSWORD | crane auth login registry-1.docker.io -u apoxy --password-stdin`,
		})
}

// BuildBackplane builds a backplane binary.
func (m *ApoxyCli) BuildBackplane(
	ctx context.Context,
	src *dagger.Directory,
	// +optional
	platform string,
	// +optional
	sccacheToken *dagger.Secret,
) *dagger.Container {
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
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
		WithExec([]string{"wget", "https://github.com/apoxy-dev/otel-collector/archive/refs/tags/v1.2.0.tar.gz"}).
		WithExec([]string{"tar", "-xvf", "v1.2.0.tar.gz"}).
		WithExec([]string{"mkdir", "-p", "/src/github.com/apoxy-dev"}).
		WithExec([]string{"mv", "otel-collector-1.2.0", "/src/github.com/apoxy-dev/otel-collector"}).
		WithEnvVariable("CGO_ENABLED", "0").
		WithWorkdir("/src/github.com/apoxy-dev/otel-collector/otelcol-apoxy").
		WithExec([]string{"go", "build", "-o", "/src/" + otelOut}).
		WithWorkdir("/src")

	runtimeCtr := m.PullEdgeRuntime(ctx, p, src, sccacheToken)

	return dag.Container(dagger.ContainerOpts{Platform: p}).
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithExec([]string{"apk", "add", "-u", "iptables", "ip6tables", "iproute2", "net-tools"}).
		WithFile("/bin/backplane", builder.File(bpOut)).
		WithFile("/bin/dial-stdio", builder.File(dsOut)).
		WithFile("/bin/otel-collector", builder.File(otelOut)).
		WithFile("/bin/edge-runtime", runtimeCtr.File("/usr/local/bin/edge-runtime")).
		WithDirectory("/etc/main", runtimeCtr.Directory("/etc/main")).
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

// BuildTunnelproxy builds a tunnel proxy binary.
func (m *ApoxyCli) BuildTunnelproxy(
	ctx context.Context,
	src *dagger.Directory,
	// +optional
	platform string,
) *dagger.Container {
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	p := dagger.Platform(platform)
	goarch := archOf(p)

	tpOut := filepath.Join("build", "tunnelproxy-"+goarch)

	builder := m.BuilderContainer(ctx, src).
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", "linux").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod-"+goarch)).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("go-build-"+goarch)).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", fmt.Sprintf("zig-wrapper cc --target=%s-linux-musl", canonArchFromGoArch(goarch))).
		WithExec([]string{"go", "build", "-ldflags", "-v -linkmode=external", "-o", tpOut, "./cmd/tunnelproxy"}).
		WithWorkdir("/src")

	return dag.Container(dagger.ContainerOpts{Platform: p}).
		From("cgr.dev/chainguard/wolfi-base:latest").
		WithExec([]string{"apk", "add", "-u", "iptables", "ip6tables", "iproute2", "net-tools", "sed", "coreutils"}).
		WithFile("/bin/tunnelproxy", builder.File(tpOut)).
		WithEntrypoint([]string{"/bin/tunnelproxy"})
}

// BuildKubeController builds a kube controller binary.
func (m *ApoxyCli) BuildKubeController(
	ctx context.Context,
	src *dagger.Directory,
	// +optional
	platform string,
) *dagger.Container {
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	p := dagger.Platform(platform)
	goarch := archOf(p)

	kcOut := filepath.Join("build", "kube-controller-"+goarch)

	builder := m.BuilderContainer(ctx, src).
		WithEnvVariable("GOARCH", goarch).
		WithEnvVariable("GOOS", "linux").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod-"+goarch)).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("go-build-"+goarch)).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CC", fmt.Sprintf("zig-wrapper cc --target=%s-linux-musl", canonArchFromGoArch(goarch))).
		WithExec([]string{"go", "build", "-ldflags", "-v -linkmode=external", "-o", kcOut, "./cmd/kube-controller"}).
		WithWorkdir("/src")

	return dag.Container(dagger.ContainerOpts{Platform: p}).
		From("ubuntu:24.04").
		WithFile("/bin/kube-controller", builder.File(kcOut)).
		WithEntrypoint([]string{"/bin/kube-controller"})
}

// PublishImages publishes images to the registry.
func (m *ApoxyCli) PublishImages(
	ctx context.Context,
	src *dagger.Directory,
	registryPassword *dagger.Secret,
	tag string,
	sha string,
	// +optional
	sccacheToken *dagger.Secret,
) error {
	var apiCtrs []*dagger.Container
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		apiCtrs = append(apiCtrs, m.BuildAPIServer(ctx, src, platform, sccacheToken))
	}

	addr, err := dag.Container().
		WithRegistryAuth(
			"registry-1.docker.io",
			"apoxy",
			registryPassword,
		).
		Publish(ctx, "docker.io/apoxy/apiserver:"+tag, dagger.ContainerPublishOpts{
			PlatformVariants: apiCtrs,
		})
	if err != nil {
		return err
	}

	fmt.Println("API server image published to", addr)

	var bCtrs []*dagger.Container
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		bCtrs = append(bCtrs, m.BuildBackplane(ctx, src, platform, sccacheToken))
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

	var tpCtrs []*dagger.Container
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		tpCtrs = append(tpCtrs, m.BuildTunnelproxy(ctx, src, platform))
	}

	addr, err = dag.Container().
		WithRegistryAuth(
			"registry-1.docker.io",
			"apoxy",
			registryPassword,
		).
		Publish(ctx, "docker.io/apoxy/tunnelproxy:"+tag, dagger.ContainerPublishOpts{
			PlatformVariants: tpCtrs,
		})
	if err != nil {
		return err
	}

	fmt.Println("Tunnelproxy images published to", addr)

	var kcCtrs []*dagger.Container
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		kcCtrs = append(kcCtrs, m.BuildKubeController(ctx, src, platform))
	}

	addr, err = dag.Container().
		WithRegistryAuth(
			"registry-1.docker.io",
			"apoxy",
			registryPassword,
		).
		Publish(ctx, "docker.io/apoxy/kube-controller:"+tag, dagger.ContainerPublishOpts{
			PlatformVariants: kcCtrs,
		})
	if err != nil {
		return err
	}

	fmt.Println("Kube controller images published to", addr)

	var cliCtrs []*dagger.Container
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		cliCtr := m.BuildCLIRelease(ctx, src, platform, tag, sha)
		cliCtrs = append(cliCtrs, cliCtr)
	}

	addr, err = dag.Container().
		WithRegistryAuth(
			"registry-1.docker.io",
			"apoxy",
			registryPassword,
		).
		Publish(ctx, "docker.io/apoxy/apoxy:"+tag, dagger.ContainerPublishOpts{
			PlatformVariants: cliCtrs,
		})
	if err != nil {
		return err
	}

	fmt.Println("Tunnelproxy images published to", addr)
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

// PublishSingleArchImages builds and publishes images for the host architecture only.
// This is meant to be run on native arch workers (amd64 and arm64) in parallel,
// then combined with PublishMultiarchImages.
func (m *ApoxyCli) PublishSingleArchImages(
	ctx context.Context,
	src *dagger.Directory,
	registryPassword *dagger.Secret,
	tag string,
	sha string,
	// +optional
	sccacheToken *dagger.Secret,
) error {
	platform := hostPlatform()
	goarch := runtime.GOARCH // amd64 or arm64

	// Build containers for native platform only.
	apiCtr := m.BuildAPIServer(ctx, src, platform, sccacheToken)
	bpCtr := m.BuildBackplane(ctx, src, platform, sccacheToken)
	tpCtr := m.BuildTunnelproxy(ctx, src, platform)
	kcCtr := m.BuildKubeController(ctx, src, platform)
	cliCtr := m.BuildCLIRelease(ctx, src, platform, tag, sha)

	// Publish with platform-specific tags.
	images := []struct {
		name string
		ctr  *dagger.Container
	}{
		{"apiserver", apiCtr},
		{"backplane", bpCtr},
		{"tunnelproxy", tpCtr},
		{"kube-controller", kcCtr},
		{"apoxy", cliCtr},
	}

	for _, img := range images {
		// Publish as a plain image (not a manifest list) so crane can combine them later.
		addr, err := img.ctr.
			WithRegistryAuth("registry-1.docker.io", "apoxy", registryPassword).
			Publish(ctx, fmt.Sprintf("docker.io/apoxy/%s:%s-%s", img.name, tag, goarch))
		if err != nil {
			return fmt.Errorf("failed to publish %s: %w", img.name, err)
		}
		fmt.Printf("Published %s image to %s\n", img.name, addr)
	}

	return nil
}

// PublishMultiarchImages combines platform-specific images into multi-arch manifests using crane.
// Run this after PublishSingleArchImages has completed on both amd64 and arm64 workers.
func (m *ApoxyCli) PublishMultiarchImages(
	ctx context.Context,
	registryPassword *dagger.Secret,
	tag string,
) error {
	images := []string{"apiserver", "backplane", "tunnelproxy", "kube-controller", "apoxy"}

	crane := m.CraneContainer(ctx, registryPassword)

	for _, img := range images {
		manifest := fmt.Sprintf("docker.io/apoxy/%s:%s", img, tag)
		craneCmd := []string{
			"crane", "index", "append",
			"--manifest", manifest + "-amd64",
			"--manifest", manifest + "-arm64",
			"--tag", manifest,
		}

		output, err := crane.WithExec(craneCmd).Stdout(ctx)
		if err != nil {
			return fmt.Errorf("failed to create multi-arch manifest for %s: %w", img, err)
		}
		fmt.Printf("Published multi-arch %s image: %s\n", img, output)
	}

	return nil
}
