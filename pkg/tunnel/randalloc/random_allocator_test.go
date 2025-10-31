package randalloc_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/randalloc"
)

// helper to build a RandAllocator[string] with deterministic items
func newAllocator(addrs ...string) *randalloc.RandAllocator[string] {
	return randalloc.NewRandAllocator(sets.New[string](addrs...))
}

func TestAcquireAndReleaseSingle(t *testing.T) {
	ra := newAllocator("r1", "r2")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addr, err := ra.Acquire(ctx)
	require.NoError(t, err, "first acquire should succeed")
	assert.Contains(t, []string{"r1", "r2"}, addr, "acquired addr must be from pool")

	// If we release it, we should be able to Acquire it again.
	ra.Release(addr)

	addr2, err := ra.Acquire(ctx)
	require.NoError(t, err, "second acquire after release should succeed")
	assert.Contains(t, []string{"r1", "r2"}, addr2)
}

func TestConcurrentUniqueAcquires(t *testing.T) {
	ra := newAllocator("a", "b", "c")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	got := make([]string, 0, 3)

	acquireOnce := func() {
		defer wg.Done()
		addr, err := ra.Acquire(ctx)
		require.NoError(t, err)

		mu.Lock()
		got = append(got, addr)
		mu.Unlock()
	}

	// Grab 3 relays in parallel; allocator size is 3
	wg.Add(3)
	for i := 0; i < 3; i++ {
		go acquireOnce()
	}
	wg.Wait()

	require.Len(t, got, 3)

	// All acquired addrs must be unique
	seen := sets.New[string]()
	for _, addr := range got {
		assert.False(t, seen.Has(addr), "duplicate addr acquired concurrently: %s", addr)
		seen.Insert(addr)
	}
}

func TestAcquireBlocksUntilRelease(t *testing.T) {
	ra := newAllocator("only-one")

	ctx1, cancel1 := context.WithTimeout(context.Background(), time.Second)
	defer cancel1()

	// First acquire should grab the only relay.
	addr1, err := ra.Acquire(ctx1)
	require.NoError(t, err)
	assert.Equal(t, "only-one", addr1)

	// Second acquire should block until we release.
	startCh := make(chan struct{})
	gotCh := make(chan string)
	errCh := make(chan error)

	go func() {
		close(startCh) // signal goroutine started
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()

		addr2, err2 := ra.Acquire(ctx2)
		if err2 != nil {
			errCh <- err2
			return
		}
		gotCh <- addr2
	}()

	// make sure goroutine is actually running before we release
	<-startCh

	// Briefly sleep to convince ourselves that goroutine would still be blocked
	time.Sleep(50 * time.Millisecond)

	select {
	case <-gotCh:
		t.Fatalf("Acquire should still be blocked before Release")
	case <-errCh:
		t.Fatalf("Acquire errored before Release")
	default:
		// good, still blocked
	}

	// Now Release the relay so the goroutine can proceed
	ra.Release("only-one")

	// Now we expect the goroutine to finish successfully with same addr
	select {
	case addr2 := <-gotCh:
		assert.Equal(t, "only-one", addr2, "after release, waiter should get freed relay")
	case err2 := <-errCh:
		t.Fatalf("blocked Acquire unexpectedly errored: %v", err2)
	case <-time.After(time.Second):
		t.Fatalf("Acquire did not unblock after Release")
	}
}

func TestAcquireContextCancel(t *testing.T) {
	ra := newAllocator("busy")

	// Take the only relay so future Acquire will block.
	ctxFirst, cancelFirst := context.WithTimeout(context.Background(), time.Second)
	defer cancelFirst()

	addr, err := ra.Acquire(ctxFirst)
	require.NoError(t, err)
	assert.Equal(t, "busy", addr)

	// Now try to Acquire again, but with a short-lived context.
	ctxBlocked, cancelBlocked := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelBlocked()

	start := time.Now()
	addr2, err2 := ra.Acquire(ctxBlocked)
	elapsed := time.Since(start)

	// We expect an error due to context timeout.
	require.Error(t, err2, "Acquire should fail due to context timeout while no relay is available")
	assert.Empty(t, addr2, "no addr should be returned on context cancel")

	// sanity check: it should have actually waited (i.e. not return instantly)
	assert.GreaterOrEqual(t, elapsed, 40*time.Millisecond)
}

func TestReleaseBroadcastsEvenIfNotInUse(t *testing.T) {
	ra := newAllocator("x")

	// Take it so allocator marks it in-use.
	ctxMain, cancelMain := context.WithTimeout(context.Background(), time.Second)
	defer cancelMain()

	addr, err := ra.Acquire(ctxMain)
	require.NoError(t, err)
	assert.Equal(t, "x", addr)

	// Now start a waiter that will block.
	gotCh := make(chan string)
	errCh := make(chan error)

	go func() {
		ctxWait, cancelWait := context.WithTimeout(context.Background(), time.Second)
		defer cancelWait()
		a, err := ra.Acquire(ctxWait)
		if err != nil {
			errCh <- err
			return
		}
		gotCh <- a
	}()

	// Release once (normal path) to free it.
	ra.Release("x")

	// Releasing again should no-op but still broadcast.
	// This mainly exercises the "if ra.inUse[item]" branch not being taken.
	// It should still wake waiters.
	ra.Release("x")

	select {
	case got := <-gotCh:
		assert.Equal(t, "x", got, "waiter should eventually acquire x")
	case err := <-errCh:
		t.Fatalf("waiter got unexpected error: %v", err)
	case <-time.After(time.Second):
		t.Fatalf("waiter did not wake after Release broadcasts")
	}
}

func TestReplaceWakesWaitersAndUsesNewSet(t *testing.T) {
	ra := newAllocator("old")

	// Take the only old item so future Acquire blocks.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	gotOld, err := ra.Acquire(ctx)
	require.NoError(t, err)
	assert.Equal(t, "old", gotOld)

	// Start a waiter that will block until Replace or Release happens.
	gotCh := make(chan string)
	errCh := make(chan error)
	go func() {
		ctxW, cancelW := context.WithTimeout(context.Background(), time.Second)
		defer cancelW()
		addr, err := ra.Acquire(ctxW)
		if err != nil {
			errCh <- err
			return
		}
		gotCh <- addr
	}()

	// Replace the set while "old" is still in use.
	ra.Replace(sets.New[string]("new1", "new2"))

	// The waiter should wake and get one of the *new* items.
	select {
	case got := <-gotCh:
		assert.Contains(t, []string{"new1", "new2"}, got, "waiter should receive an item from the NEW set after Replace()")
	case err := <-errCh:
		t.Fatalf("waiter got unexpected error: %v", err)
	case <-time.After(time.Second):
		t.Fatalf("waiter did not wake after Replace() broadcast")
	}
}

func TestReplaceRemovesOldItemsOnceReleased(t *testing.T) {
	ra := newAllocator("keep", "drop")

	// Acquire both items so allocator marks them in use.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a1, err := ra.Acquire(ctx)
	require.NoError(t, err)
	a2, err := ra.Acquire(ctx)
	require.NoError(t, err)
	got := sets.New[string](a1, a2)
	require.True(t, got.Has("keep") && got.Has("drop"), "sanity: acquired both keep and drop")

	// Replace the item set: keep "keep", drop "drop", add "new".
	ra.Replace(sets.New[string]("keep", "new"))

	// Release both old items.
	ra.Release("drop")
	ra.Release("keep")

	// Now future acquires should *never* return "drop".
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()

	seen := sets.New[string]()
	for i := 0; i < 2; i++ {
		addr, err := ra.Acquire(ctx2)
		require.NoError(t, err)
		seen.Insert(addr)
	}

	// We only expect {"keep","new"} to be available.
	assert.False(t, seen.Has("drop"), `"drop" should not be reissued after being removed by Replace`)
	assert.Equal(t, sets.New[string]("keep", "new"), seen, "post-Replace pool should be exactly keep+new")
}

func TestReplaceSubsetAndReacquireBehavior(t *testing.T) {
	ra := newAllocator("a", "b", "c")

	// Acquire two so they're marked in-use.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := ra.Acquire(ctx)
	require.NoError(t, err)
	second, err := ra.Acquire(ctx)
	require.NoError(t, err)

	inUse := sets.New[string](first, second)
	require.Len(t, inUse, 2)

	// Replace with a subset that keeps only "b" plus add "d".
	ra.Replace(sets.New[string]("b", "d"))

	// Release both in-use items; only "b" should be eligible again (if it was one of the in-use),
	// and "d" should be available. Any item not in the new set (like "a" or "c") must not reappear.
	for _, it := range inUse.UnsortedList() {
		ra.Release(it)
	}

	// Collect the next two acquires.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()

	got := sets.New[string]()
	for i := 0; i < 2; i++ {
		addr, err := ra.Acquire(ctx2)
		require.NoError(t, err)
		got.Insert(addr)
	}

	// Expect only from {"b","d"}; never "a" or "c".
	assert.Subset(t, []string{"b", "d"}, got.UnsortedList(), "acquires should come from the new set only")
	assert.False(t, got.Has("a"), `"a" was removed by Replace and should not be returned`)
	assert.False(t, got.Has("c"), `"c" was removed by Replace and should not be returned`)
}
