//go:build !linux

package router_test

import (
	"testing"

	"github.com/apoxy-dev/apoxy/pkg/utils/vm"
)

// A stub for non-linux operating systems, when the test is compiled for the VM
// it will use the linux version of this test.
func TestNewClientNetlinkRouter(t *testing.T) {
	// Run the test in a linux VM.
	vm.RunTestInVM(t)
}

func TestClientNetlinkRouter_AddRoute(t *testing.T) {
	// Run the test in a linux VM.
	vm.RunTestInVM(t)
}

func TestClientNetlinkRouter_DelRoute(t *testing.T) {
	// Run the test in a linux VM.
	vm.RunTestInVM(t)
}

func TestClientNetlinkRouter_StartStop(t *testing.T) {
	// Run the test in a linux VM.
	vm.RunTestInVM(t)
}

func TestClientNetlinkRouter_IPv6Routes(t *testing.T) {
	// Run the test in a linux VM.
	vm.RunTestInVM(t)
}

func TestClientNetlinkRouter_DefaultRoutes(t *testing.T) {
	// Run the test in a linux VM.
	vm.RunTestInVM(t)
}
