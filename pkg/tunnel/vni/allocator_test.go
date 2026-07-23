package vni

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVNIAllocatorBasics(t *testing.T) {
	a := NewVNIAllocator()

	first, err := a.Allocate()
	require.NoError(t, err)
	require.EqualValues(t, 1, first, "VNI 0 is reserved; allocation starts at 1")

	second, err := a.Allocate()
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}

func TestVNIAllocatorQuarantineOnRelease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := NewVNIAllocator(WithQuarantineWindow(30 * time.Second))
	a.now = func() time.Time { return now }

	v1, err := a.Allocate()
	require.NoError(t, err)

	a.Release(v1)

	// Still within the quarantine window: the released VNI must not be reused.
	v2, err := a.Allocate()
	require.NoError(t, err)
	require.NotEqual(t, v1, v2, "released VNI is quarantined, not immediately reused")

	// After the window elapses, the next allocation may reclaim it (lowest free).
	now = now.Add(31 * time.Second)
	a.Release(v2)
	now = now.Add(31 * time.Second)
	v3, err := a.Allocate()
	require.NoError(t, err)
	require.Equal(t, v1, v3, "quarantined VNI is reclaimed once its window elapses")
}

func TestVNIAllocatorReleaseIgnoresReserved(t *testing.T) {
	a := NewVNIAllocator()
	require.NotPanics(t, func() { a.Release(0) })
	require.NotPanics(t, func() { a.Release(1 << 24) }) // out of range
}
