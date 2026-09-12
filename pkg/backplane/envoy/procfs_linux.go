//go:build linux

package envoy

import "os"

// hostProcfs reads the counters of the pod, which shares its proc filesystem
// and its network namespace with Envoy.
var hostProcfs = &procfs{root: "/proc", pageSize: int64(os.Getpagesize())}

// systemReaders returns the readers for the process and the network counters.
var systemReaders = func() (processReader, netReader) {
	return hostProcfs, hostProcfs
}
