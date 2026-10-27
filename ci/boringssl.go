package main

import (
	"dagger/apoxy-cli/internal/dagger"
)

// BoringSSL builds the pinned BoringSSL with ci/boringssl.sh in a Go container of platform (the
// engine platform when empty), and returns its include/ and lib/libcrypto.a.
func (m *ApoxyCli) BoringSSL(
	// +optional
	platform dagger.Platform,
) *dagger.Directory {
	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("golang:1.26.8-bookworm").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", "cmake", "ninja-build"}).
		WithFile("/boringssl.sh", dag.CurrentModule().Source().File("boringssl.sh")).
		WithExec([]string{"sh", "/boringssl.sh", "/boringssl"}).
		Directory("/boringssl")
}

// withBoringSSL adds BoringSSL of platform to the Go container ctr of the same platform, with the
// cgo flags that boringssl.sh prints for /boringssl. The cgo packages of ctr link it.
func (m *ApoxyCli) withBoringSSL(ctr *dagger.Container, platform dagger.Platform) *dagger.Container {
	return ctr.
		WithDirectory("/boringssl", m.BoringSSL(platform)).
		WithEnvVariable("CGO_ENABLED", "1").
		WithEnvVariable("CGO_CFLAGS", "-O2 -g -I/boringssl/include").
		WithEnvVariable("CGO_LDFLAGS", "/boringssl/lib/libcrypto.a -lstdc++ -lpthread")
}
