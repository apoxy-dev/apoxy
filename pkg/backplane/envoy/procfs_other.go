//go:build !linux

package envoy

// systemReaders returns no readers. Only Linux publishes the process and the
// network counters the runtime reports.
var systemReaders = func() (processReader, netReader) {
	return nil, nil
}
