package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/pkg/net/lwtunnel"
)

func TestTunnelNodeReconciler_Reconcile(t *testing.T) {
	// Skip if not running as root (required for netlink operations)
	if !isRoot() {
		t.Skip("Test requires root privileges")
	}

	scheme := runtime.NewScheme()
	_ = corev1alpha.AddToScheme(scheme)

	tests := []struct {
		name          string
		tunnelNode    *corev1alpha.TunnelNode
		interfaceName string
		overlayIPv6   string
		expectError   bool
		validateFunc  func(t *testing.T, r *TunnelNodeReconciler)
	}{
		{
			name:          "create geneve tunnel with agents",
			interfaceName: "test-geneve0",
			overlayIPv6:   "fd00::1/64",
			tunnelNode: &corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tunnel",
				},
				Status: corev1alpha.TunnelNodeStatus{
					Agents: []corev1alpha.AgentStatus{
						{
							Name:           "agent-1",
							PrivateAddress: "192.168.1.10",
							AgentAddress:   "fd00::10",
						},
						{
							Name:           "agent-2",
							PrivateAddress: "192.168.1.11",
							AgentAddress:   "fd00::11",
						},
					},
				},
			},
			expectError: false,
			validateFunc: func(t *testing.T, r *TunnelNodeReconciler) {
				// Check interface exists
				link, err := netlink.LinkByName(r.gnvDev)
				require.NoError(t, err)
				assert.NotNil(t, link)

				// Check interface is up
				assert.Equal(t, "up", link.Attrs().OperState.String())

				// Verify it's a Geneve interface
				_, ok := link.(*netlink.Geneve)
				assert.True(t, ok, "Interface is not Geneve type")

				// Check IPv6 address
				addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
				require.NoError(t, err)
				found := false
				for _, addr := range addrs {
					if addr.IPNet.String() == "fd00::1/64" {
						found = true
						break
					}
				}
				assert.True(t, found, "IPv6 address not found on interface")

				// Check routes exist
				routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
				require.NoError(t, err)

				expectedRoutes := map[string]string{
					"fd00::10/128": "192.168.1.10",
					"fd00::11/128": "192.168.1.11",
				}

				for dst, remote := range expectedRoutes {
					found := false
					for _, route := range routes {
						if route.Dst != nil && route.Dst.String() == dst && route.Encap != nil {
							if geneveEncap, ok := route.Encap.(*lwtunnel.IPEncap); ok {
								if geneveEncap.Remote.String() == remote {
									found = true
									// Verify encapsulation parameters
									assert.Equal(t, uint32(100), geneveEncap.ID, "Incorrect VNI in route encapsulation")
									break
								}
							}
						}
					}
					assert.True(t, found, "Route %s with Geneve encap to %s not found", dst, remote)
				}
			},
		},
		{
			name:          "create geneve tunnel with single agent",
			interfaceName: "test-geneve-single",
			overlayIPv6:   "fd01::1/64",
			tunnelNode: &corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tunnel-single",
				},
				Status: corev1alpha.TunnelNodeStatus{
					Agents: []corev1alpha.AgentStatus{
						{
							Name:           "agent-single",
							PrivateAddress: "10.0.0.5",
							AgentAddress:   "fd01::5",
						},
					},
				},
			},
			expectError: false,
			validateFunc: func(t *testing.T, r *TunnelNodeReconciler) {
				// Check interface exists
				link, err := netlink.LinkByName(r.gnvDev)
				require.NoError(t, err)
				assert.NotNil(t, link)

				// Verify it's a Geneve interface
				geneve, ok := link.(*netlink.Geneve)
				require.True(t, ok, "Interface is not Geneve type")
				assert.Equal(t, uint32(100), geneve.ID, "Incorrect VNI")
				// Verify no remote is set (multi-point mode)
				assert.Nil(t, geneve.Remote, "Remote should not be set for multi-point tunnel")
				assert.Nil(t, geneve.Remote6, "Remote6 should not be set for multi-point tunnel")
			},
		},
		{
			name:          "skip agent with invalid addresses",
			interfaceName: "test-geneve-invalid",
			overlayIPv6:   "fd02::1/64",
			tunnelNode: &corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tunnel-invalid",
				},
				Status: corev1alpha.TunnelNodeStatus{
					Agents: []corev1alpha.AgentStatus{
						{
							Name:           "invalid-agent-1",
							PrivateAddress: "not-an-ip",
							AgentAddress:   "fd02::10",
						},
						{
							Name:           "invalid-agent-2",
							PrivateAddress: "192.168.1.20",
							AgentAddress:   "not-an-ipv6",
						},
						{
							Name:           "valid-agent",
							PrivateAddress: "192.168.1.21",
							AgentAddress:   "fd02::21",
						},
					},
				},
			},
			expectError: false,
			validateFunc: func(t *testing.T, r *TunnelNodeReconciler) {
				// Check interface exists
				link, err := netlink.LinkByName(r.gnvDev)
				require.NoError(t, err)

				// Check only valid route exists
				routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
				require.NoError(t, err)

				foundValidRoute := false
				found := false
				for _, route := range routes {
					if route.Dst != nil && route.Dst.String() == "fd02::21/128" && route.Encap != nil {
						if geneveEncap, ok := route.Encap.(*lwtunnel.IPEncap); ok {
							if geneveEncap.Remote.String() == "192.168.1.21" {
								foundValidRoute = true
								break
							}
						}
					}
				}
				assert.True(t, foundValidRoute, "Valid route with Geneve encapsulation not found")
			},
		},
		{
			name:          "reject IPv4 overlay address",
			interfaceName: "test-geneve-ipv4",
			overlayIPv6:   "fd03::1/64",
			tunnelNode: &corev1alpha.TunnelNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tunnel-ipv4",
				},
				Status: corev1alpha.TunnelNodeStatus{
					Agents: []corev1alpha.AgentStatus{
						{
							Name:           "ipv4-agent",
							PrivateAddress: "192.168.1.30",
							AgentAddress:   "10.0.0.30", // IPv4 overlay address
						},
					},
				},
			},
			expectError: false,
			validateFunc: func(t *testing.T, r *TunnelNodeReconciler) {
				// Check interface exists but no routes added
				link, err := netlink.LinkByName(r.gnvDev)
				require.NoError(t, err)

				routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
				require.NoError(t, err)

				// Should not have any routes for IPv4 overlay addresses
				for _, route := range routes {
					if route.Dst != nil && route.Encap != nil {
						if geneveEncap, ok := route.Encap.(*lwtunnel.IPEncap); ok {
							if geneveEncap.Remote.String() == "192.168.1.30" {
								t.Errorf("Found route for IPv4 overlay address, which should be rejected")
							}
						}
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any existing interface
			if link, err := netlink.LinkByName(tt.interfaceName); err == nil {
				_ = netlink.LinkDel(link)
			}

			// Create fake client with tunnel node
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.tunnelNode).
				Build()

			// Create reconciler
			r := NewTunnelNodeReconciler(fakeClient, tt.interfaceName)
			if tt.overlayIPv6 != "" {
				r = r.WithOverlayIPv6CIDR(tt.overlayIPv6)
			}

			// Reconcile
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.tunnelNode.Name,
				},
			}

			_, err := r.Reconcile(context.Background(), req)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Validate
			if tt.validateFunc != nil {
				tt.validateFunc(t, r)
			}

			// Cleanup
			if link, err := netlink.LinkByName(tt.interfaceName); err == nil {
				_ = netlink.LinkDel(link)
			}
		})
	}
}

func TestTunnelNodeReconciler_DeleteTunnelNode(t *testing.T) {
	if !isRoot() {
		t.Skip("Test requires root privileges")
	}

	scheme := runtime.NewScheme()
	_ = corev1alpha.AddToScheme(scheme)

	interfaceName := "test-delete-geneve"

	// Create interface first
	geneve := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: interfaceName,
			MTU:  1400,
		},
		ID:   100,
		Port: 6081,
	}
	err := netlink.LinkAdd(geneve)
	require.NoError(t, err)

	// Verify interface exists
	_, err = netlink.LinkByName(interfaceName)
	require.NoError(t, err)

	// Create fake client without tunnel node (simulating deletion)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create reconciler
	r := NewTunnelNodeReconciler(fakeClient, interfaceName)

	// Reconcile with non-existent tunnel node
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: "deleted-tunnel",
		},
	}

	_, err = r.Reconcile(context.Background(), req)
	assert.NoError(t, err)

	// Verify interface was deleted
	_, err = netlink.LinkByName(interfaceName)
	assert.Error(t, err, "Interface should have been deleted")
}

func TestTunnelNodeReconciler_RouteManagement(t *testing.T) {
	if !isRoot() {
		t.Skip("Test requires root privileges")
	}

	scheme := runtime.NewScheme()
	_ = corev1alpha.AddToScheme(scheme)

	interfaceName := "test-route-mgmt"

	// Initial tunnel node with two agents
	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-tunnel-routes",
		},
		Status: corev1alpha.TunnelNodeStatus{
			Agents: []corev1alpha.AgentStatus{
				{
					Name:           "agent-1",
					PrivateAddress: "192.168.1.10",
					AgentAddress:   "fd00::10",
				},
				{
					Name:           "agent-2",
					PrivateAddress: "192.168.1.11",
					AgentAddress:   "fd00::11",
				},
			},
		},
	}

	// Clean up any existing interface
	if link, err := netlink.LinkByName(interfaceName); err == nil {
		_ = netlink.LinkDel(link)
	}

	// Create fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	// Create reconciler
	r := NewTunnelNodeReconciler(fakeClient, interfaceName).
		WithOverlayIPv6CIDR("fd00::1/64")

	// First reconciliation
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: tunnelNode.Name,
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	// Verify routes exist
	link, err := netlink.LinkByName(interfaceName)
	require.NoError(t, err)

	routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
	require.NoError(t, err)

	routeCount := 0
	for _, route := range routes {
		if route.Dst != nil && route.Encap != nil {
			if _, ok := route.Encap.(*lwtunnel.IPEncap); ok {
				routeCount++
			}
		}
	}
	assert.Equal(t, 2, routeCount, "Should have 2 routes with Geneve encapsulation")

	// Update tunnel node - remove agent-1, keep agent-2
	tunnelNode.Status.Agents = []corev1alpha.AgentStatus{
		{
			Name:           "agent-2",
			PrivateAddress: "192.168.1.11",
			AgentAddress:   "fd00::11",
		},
	}

	// Update in fake client
	err = fakeClient.Update(context.Background(), tunnelNode)
	require.NoError(t, err)

	// Second reconciliation
	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	// Verify only agent-2 route exists
	routes, err = netlink.RouteList(link, netlink.FAMILY_V6)
	require.NoError(t, err)

	found := false
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == "fd00::11/128" && route.Encap != nil {
			if geneveEncap, ok := route.Encap.(*lwtunnel.IPEncap); ok {
				if geneveEncap.Remote.String() == "192.168.1.11" {
					found = true
				}
			}
		}
		// Should not find route for agent-1
		if route.Dst != nil && route.Dst.String() == "fd00::10/128" {
			t.Errorf("Found stale route for removed agent-1")
		}
	}
	assert.True(t, found, "Route for agent-2 with Geneve encapsulation should still exist")

	// Cleanup
	_ = netlink.LinkDel(link)
}

func TestTunnelNodeReconciler_Configuration(t *testing.T) {
	if !isRoot() {
		t.Skip("Test requires root privileges")
	}

	scheme := runtime.NewScheme()
	_ = corev1alpha.AddToScheme(scheme)

	interfaceName := "test-config-geneve"

	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-tunnel-config",
		},
		Status: corev1alpha.TunnelNodeStatus{
			Agents: []corev1alpha.AgentStatus{
				{
					Name:           "agent-config",
					PrivateAddress: "172.16.0.10",
					AgentAddress:   "fd10::10",
				},
			},
		},
	}

	// Clean up any existing interface
	if link, err := netlink.LinkByName(interfaceName); err == nil {
		_ = netlink.LinkDel(link)
	}

	// Create fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	// Create reconciler with custom configuration
	r := NewTunnelNodeReconciler(fakeClient, interfaceName).
		WithOverlayIPv6CIDR("fd10::1/64").
		WithLocalVTEP("10.1.1.1").
		WithVNI(200).
		WithPort(6082).
		WithMTU(1450)

	// Reconcile
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: tunnelNode.Name,
		},
	}

	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	// Verify custom configuration
	link, err := netlink.LinkByName(interfaceName)
	require.NoError(t, err)

	geneve, ok := link.(*netlink.Geneve)
	require.True(t, ok, "Interface is not Geneve type")

	// Check custom VNI
	assert.Equal(t, uint32(200), geneve.ID, "Custom VNI not applied")

	// Check custom MTU
	assert.Equal(t, 1450, link.Attrs().MTU, "Custom MTU not applied")

	// Check custom port
	assert.Equal(t, uint16(6082), geneve.Port, "Custom port not applied")

	// Verify route uses custom encapsulation parameters
	routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
	require.NoError(t, err)

	for _, route := range routes {
		if route.Dst != nil && route.Encap != nil {
			if geneveEncap, ok := route.Encap.(*lwtunnel.IPEncap); ok {
				assert.Equal(t, uint32(200), geneveEncap.ID, "Custom VNI not used in route encapsulation")
			}
		}
	}

	// Cleanup
	_ = netlink.LinkDel(link)
}

// Helper function to check if running as root
func isRoot() bool {
	return netlink.LinkList() != nil
}
