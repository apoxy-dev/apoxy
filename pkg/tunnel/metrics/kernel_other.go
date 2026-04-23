//go:build !linux

package metrics

// Non-Linux stub: /proc/net/snmp6 and /sys/class/net don't exist, so we skip
// registering the kernel collector. Tests on macOS still link this package
// without a registration panic.
