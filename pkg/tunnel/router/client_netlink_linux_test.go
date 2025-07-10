//go:build linux

package router

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/utils/vm"
)

// mockConnection implements connection.Connection for testing
type mockConnection struct {
	readData  []byte
	writeData [][]byte
	closed    bool
}

func newMockConnection(data []byte) *mockConnection {
	return &mockConnection{
		readData:  data,
		writeData: make([][]byte, 0),
	}
}

func (m *mockConnection) ReadPacket(buf []byte) (int, error) {
	if m.closed {
		return 0, net.ErrClosed
	}
	if len(m.readData) == 0 {
		// Block to simulate waiting for data
		time.Sleep(10 * time.Millisecond)
		return 0, nil
	}
	n := copy(buf, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockConnection) WritePacket(data []byte) ([]byte, error) {
	if m.closed {
		return nil, net.ErrClosed
	}
	m.writeData = append(m.writeData, append([]byte(nil), data...))
	return data, nil
}

func (m *mockConnection) Close() error {
	m.closed = true
	return nil
}

func TestNewClientNetlinkRouter(t *testing.T) {
	// Run the test in a linux VM
	child := vm.RunTestInVM(t)
	if !child {
		return
	}

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test basic router creation
	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun0"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	require.NotNil(t, router)

	defer router.Close()

	// Test that local addresses are configured correctly
	addrs, err := router.LocalAddresses()
	require.NoError(t, err)
	assert.Contains(t, addrs, localAddr)
}

func TestClientNetlinkRouter_AddRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun1"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	// Test adding a route
	dstPrefix, err := netip.ParsePrefix("192.168.1.0/24")
	require.NoError(t, err)

	mockConn := newMockConnection([]byte("test packet"))
	err = router.AddAddr(dstPrefix, mockConn)
	require.NoError(t, err)
	err = router.AddRoute(dstPrefix)
	require.NoError(t, err)

	// Verify route was added
	routes, err := router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 1)
	assert.Equal(t, dstPrefix, routes[0].Dst)
	assert.Equal(t, TunnelRouteStateActive, routes[0].State)
}

func TestClientNetlinkRouter_DelRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun2"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	// Add a route first
	dstPrefix, err := netip.ParsePrefix("192.168.2.0/24")
	require.NoError(t, err)

	mockConn := newMockConnection([]byte("test packet"))
	err = router.AddAddr(dstPrefix, mockConn)
	require.NoError(t, err)
	err = router.AddRoute(dstPrefix)
	require.NoError(t, err)

	// Verify route exists
	routes, err := router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 1)

	// Delete the route
	err = router.DelRoute(dstPrefix)
	require.NoError(t, err)
	err = router.DelAddr(dstPrefix)
	require.NoError(t, err)

	// Verify route was removed
	routes, err = router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 0)

	// Verify connection was closed
	assert.True(t, mockConn.closed)
}

func TestClientNetlinkRouter_StartStop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun3"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)

	// Start router in background
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	startErr := make(chan error, 1)
	go func() {
		startErr <- router.Start(ctx)
	}()

	// Give router time to start
	time.Sleep(100 * time.Millisecond)

	// Add a route while router is running
	dstPrefix, err := netip.ParsePrefix("192.168.3.0/24")
	require.NoError(t, err)

	mockConn := newMockConnection([]byte("test packet"))
	err = router.AddAddr(dstPrefix, mockConn)
	require.NoError(t, err)
	err = router.AddRoute(dstPrefix)
	require.NoError(t, err)

	// Cancel context to stop router
	cancel()

	// Wait for router to stop
	select {
	case err := <-startErr:
		// Context cancellation should not be treated as an error in this test
		if err != nil && err != context.Canceled {
			t.Errorf("Router start returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Router did not stop within timeout")
	}
}

func TestClientNetlinkRouter_IPv6Routes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("2001:db8::1/64")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun4"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	// Test adding IPv6 route
	dstPrefix, err := netip.ParsePrefix("2001:db8:1::/64")
	require.NoError(t, err)

	mockConn := newMockConnection([]byte("test ipv6 packet"))
	err = router.AddAddr(dstPrefix, mockConn)
	require.NoError(t, err)
	err = router.AddRoute(dstPrefix)
	require.NoError(t, err)

	// Verify route was added
	routes, err := router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 1)
	assert.Equal(t, dstPrefix, routes[0].Dst)
}

func TestClientNetlinkRouter_RouteUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun5"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	dstPrefix, err := netip.ParsePrefix("192.168.4.0/24")
	require.NoError(t, err)

	// Add initial route
	mockConn1 := newMockConnection([]byte("test packet 1"))
	err = router.AddAddr(dstPrefix, mockConn1)
	require.NoError(t, err)
	err = router.AddRoute(dstPrefix)
	require.NoError(t, err)

	// Update with new connection - should replace existing
	mockConn2 := newMockConnection([]byte("test packet 2"))
	err = router.AddAddr(dstPrefix, mockConn2)
	require.NoError(t, err)

	// Verify old connection was closed and route still exists
	assert.True(t, mockConn1.closed)
	routes, err := router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 1)
}

func TestClientNetlinkRouter_NonExistentRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun6"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	dstPrefix, err := netip.ParsePrefix("192.168.5.0/24")
	require.NoError(t, err)

	// Should handle non-existent routes gracefully
	err = router.DelRoute(dstPrefix)
	require.NoError(t, err)
}

func TestClientNetlinkRouter_DefaultRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun-default"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	// Test IPv4 default route
	defaultIPv4, err := netip.ParsePrefix("0.0.0.0/0")
	require.NoError(t, err)

	mockConn := newMockConnection([]byte("default packet"))
	err = router.AddAddr(defaultIPv4, mockConn)
	require.NoError(t, err)
	err = router.AddRoute(defaultIPv4)
	require.NoError(t, err)

	routes, err := router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 1)
	assert.Equal(t, defaultIPv4, routes[0].Dst)
	assert.Equal(t, "client-default", routes[0].TunID)
}

func TestClientNetlinkRouter_DefaultRoutePreservation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun-preserve"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	// Test that router can handle default routes (preservation logic)
	defaultRoute, err := netip.ParsePrefix("0.0.0.0/0")
	require.NoError(t, err)

	mockConn := newMockConnection([]byte("default"))
	err = router.AddAddr(defaultRoute, mockConn)
	require.NoError(t, err)
	err = router.AddRoute(defaultRoute)
	require.NoError(t, err)

	// Verify route was added
	routes, err := router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 1)
	assert.Equal(t, "client-default", routes[0].TunID)

	// Remove should work without errors
	err = router.DelRoute(defaultRoute)
	require.NoError(t, err)
	err = router.DelAddr(defaultRoute)
	require.NoError(t, err)
}

func TestClientNetlinkRouter_ConnectionWithLocalAddresses(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	localAddr, err := netip.ParsePrefix("10.0.0.1/24")
	require.NoError(t, err)

	router, err := NewClientNetlinkRouter(
		WithTunnelInterface("test-tun-conn-addr"),
		WithLocalAddresses([]netip.Prefix{localAddr}),
	)
	require.NoError(t, err)
	defer router.Close()

	// Test connection that provides local addresses
	mockConnWithAddrs := &mockConnectionWithAddresses{
		mockConnection: mockConnection{readData: []byte("test")},
		localAddresses: []netip.Prefix{
			netip.MustParsePrefix("192.168.100.1/32"),
		},
	}

	defaultRoute, err := netip.ParsePrefix("0.0.0.0/0")
	require.NoError(t, err)

	err = router.AddAddr(defaultRoute, mockConnWithAddrs)
	require.NoError(t, err)
	err = router.AddRoute(defaultRoute)
	require.NoError(t, err)

	routes, err := router.ListRoutes()
	require.NoError(t, err)
	assert.Len(t, routes, 1)
}

// mockConnectionWithAddresses implements both connection.Connection and LocalAddresses interface
type mockConnectionWithAddresses struct {
	mockConnection
	localAddresses []netip.Prefix
}

func (m *mockConnectionWithAddresses) LocalAddresses() ([]netip.Prefix, error) {
	return m.localAddresses, nil
}
