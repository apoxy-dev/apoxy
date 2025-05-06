package router_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/router"
)

func TestNetstackRouter(t *testing.T) {
	r, err := router.NewNetstackRouter()
	require.NoError(t, err)
	require.NotNil(t, r)

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
	conn := connection.NewMuxedConnection()
	_, _, err = r.AddPeer(prefix, conn)
	require.NoError(t, err)

	// Test RemovePeer
	err = r.RemovePeer(prefix)
	require.NoError(t, err)

	// Test Close
	cancel()

	err = g.Wait()
	require.NoError(t, err)
}
