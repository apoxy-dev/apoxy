//go:build !linux

package sandbox

// DispatchRunsc is a no-op on non-linux platforms. The gVisor runsc
// dispatch (and the sentrystack PluginStack registration) is linux-only;
// off-platform builds exist solely to keep `go build ./...` /
// `go vet ./...` green for cross-platform contributors, so the host's
// normal control loop is the only meaningful path.
func DispatchRunsc() {}
