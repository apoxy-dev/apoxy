//go:build linux

package router_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/utils/vm"
)

func TestNetlinkRouter(t *testing.T) {
	// Run the test in a linux VM
	child := vm.RunTestInVM(t)
	if !child {
		return
	}

	r, err := router.NewNetlinkRouter()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Start the router
	var g errgroup.Group

	g.Go(func() error {
		return r.Start(ctx)
	})

	t.Cleanup(func() {
		require.NoError(t, r.Close())
	})

	time.Sleep(100 * time.Millisecond) // Give some time for the router to start

	// Test AddPeer
	prefix := netip.MustParsePrefix("fd00::1/128")
	conn := connection.NewDstMuxedConn()
	require.NoError(t, r.AddAddr(prefix, conn))
	require.NoError(t, r.AddRoute(prefix))

	// Test RemovePeer
	err = r.DelRoute(prefix)
	require.NoError(t, err)
	err = r.DelAddr(prefix)
	require.NoError(t, err)

	// Test Close
	cancel()

	err = g.Wait()
	require.NoError(t, err)
}
