//go:build linux

package sandbox

import (
	"net/netip"
	"testing"
)

// allocateIPs hands out sequential /30s from 10.200.0.0/16 via a process-global
// atomic counter. The absolute values depend on prior allocations in the test
// binary, so assert the structural invariants rather than fixed addresses:
//   - container == gateway+1 (gw is subnetbase+1, ctr is subnetbase+2)
//   - both inside 10.200.0.0/16
//   - consecutive allocations advance one /30 (gateway+4)
func TestAllocateIPs(t *testing.T) {
	pool := netip.MustParsePrefix("10.200.0.0/16")

	gw1, ctr1, err := allocateIPs()
	if err != nil {
		t.Fatalf("allocateIPs #1: %v", err)
	}
	gw2, ctr2, err := allocateIPs()
	if err != nil {
		t.Fatalf("allocateIPs #2: %v", err)
	}

	if ctr1 != gw1.Next() {
		t.Errorf("container should be gateway+1: gw=%v ctr=%v", gw1, ctr1)
	}
	if ctr2 != gw2.Next() {
		t.Errorf("container should be gateway+1: gw=%v ctr=%v", gw2, ctr2)
	}
	if !pool.Contains(gw1) || !pool.Contains(ctr1) || !pool.Contains(gw2) || !pool.Contains(ctr2) {
		t.Errorf("addresses must be within %v: gw1=%v ctr1=%v gw2=%v ctr2=%v", pool, gw1, ctr1, gw2, ctr2)
	}
	// Next /30 is four addresses on: gw2 == gw1 + 4.
	gw1Plus4 := gw1.Next().Next().Next().Next()
	if gw2 != gw1Plus4 {
		t.Errorf("consecutive allocations must advance one /30 (gw+4): gw1=%v gw2=%v want=%v", gw1, gw2, gw1Plus4)
	}
	if gw1 == gw2 || ctr1 == ctr2 {
		t.Errorf("consecutive allocations must be distinct: gw1=%v gw2=%v ctr1=%v ctr2=%v", gw1, gw2, ctr1, ctr2)
	}
	if !gw1.Is4() || !ctr1.Is4() {
		t.Errorf("allocations must be IPv4: gw1=%v ctr1=%v", gw1, ctr1)
	}
}
