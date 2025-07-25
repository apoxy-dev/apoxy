package controllers

import (
	"context"
	goerrors "errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy/api/controllers/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

const (
	defaultGeneveDev  = "gnv0"
	defaultGenevePort = 6081
	defaultGeneveVNI  = 100
	defaultGeneveMTU  = 1400

	rtProtocol = 0x61
)

var _ reconcile.Reconciler = &TunnelNodeReconciler{}

// TunnelNodeReconciler reconciles TunnelNode objects and manages L3 Geneve tunnels.
type TunnelNodeReconciler struct {
	client.Client

	proxyName        string
	proxyReplicaName string

	// gnvDev is the name of the Geneve interface.
	gnvDev string
	// gnvVNI is the Virtual Network Identifier.
	gnvVNI uint32
	// gnvPort is the UDP port for Geneve.
	gnvPort uint16
	// gnvMTU is the MTU for the Geneve interface.
	gnvMTU int
}

// NewTunnelNodeReconciler returns a new TunnelNode reconciler for Geneve tunnels.
func NewTunnelNodeReconciler(
	c client.Client,
	proxyName, proxyReplicaName string,
) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		Client: c,

		proxyName:        proxyName,
		proxyReplicaName: proxyReplicaName,

		gnvDev:  defaultGeneveDev,
		gnvVNI:  defaultGeneveVNI,
		gnvPort: defaultGenevePort,
		gnvMTU:  defaultGeneveMTU,
	}
}

// WithGeneveDevice sets the name of the Geneve interface.
func (r *TunnelNodeReconciler) WithGeneveDevice(dev string) *TunnelNodeReconciler {
	r.gnvDev = dev
	return r
}

// WithGeneveVNI sets the Virtual Network Identifier.
func (r *TunnelNodeReconciler) WithGeneveVNI(vni uint32) *TunnelNodeReconciler {
	r.gnvVNI = vni
	return r
}

// WithGenevePort sets the UDP port for Geneve.
func (r *TunnelNodeReconciler) WithGenevePort(port uint16) *TunnelNodeReconciler {
	r.gnvPort = port
	return r
}

// WithGeneveMTU sets the MTU for the Geneve interface.
func (r *TunnelNodeReconciler) WithGeneveMTU(mtu int) *TunnelNodeReconciler {
	r.gnvMTU = mtu
	return r
}

func (r *TunnelNodeReconciler) hwAddr(ula *tunnet.NetULA) net.HardwareAddr {
	// Use 2-byte endpoint portion of the ULA address [11:13].
	// TODO(dilyevsky): Make this strongly typed.
	return net.HardwareAddr([]byte{0x0A, 0x00, 0x00, 0x00, ula.EndpointID[0], ula.EndpointID[1]})
}

// Reconcile implements reconcile.Reconciler.
func (r *TunnelNodeReconciler) Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)
	log.Info("Reconciling TunnelNode")

	tunnelNode := &corev1alpha.TunnelNode{}
	if err := r.Get(ctx, request.NamespacedName, tunnelNode); err != nil {
		if errors.IsNotFound(err) {
			log.Info("TunnelNode not found, cleaning up Geneve interface", "name", request.NamespacedName)
			return ctrl.Result{}, r.cleanupGeneve(ctx)
		}
		log.Error(err, "Failed to get TunnelNode")
		return ctrl.Result{}, err
	}

	proxy := &ctrlv1alpha1.Proxy{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.proxyName}, proxy); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Proxy not found")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Proxy")
		return ctrl.Result{}, err
	}
	rs, found := findReplicaStatus(proxy, r.proxyReplicaName)
	if !found {
		log.Info("Proxy replica not found")
		return ctrl.Result{}, nil
	}
	if rs.Address == "" {
		log.Info("Proxy replica address not found")
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
	}
	addr, err := netip.ParsePrefix(rs.Address)
	if err != nil {
		log.Error(err, "Failed to parse address", "address", rs.Address)
		return ctrl.Result{}, err
	}
	ula, err := tunnet.ULAFromPrefix(ctx, addr)
	if err != nil {
		log.Error(err, "Failed to parse address", "address", rs.Address)
		return ctrl.Result{}, err
	}

	log = log.WithValues("proxyReplica", rs.Name, "address", addr)
	ctx = clog.IntoContext(ctx, log)
	log.Info("Reconciling tunnel device")

	if err := r.ensureDevice(ctx, ula); err != nil {
		log.Error(err, "Failed to ensure Geneve interface")
		return ctrl.Result{}, err
	}

	curRoutes, err := r.routeList(ctx)
	if err != nil {
		log.Error(err, "Failed to get current routes")
		return ctrl.Result{}, err
	}
	updRoutes := sets.New[netip.Prefix]()

	for _, agent := range tunnelNode.Status.Agents {
		if agent.PrivateAddress == "" || agent.AgentAddress == "" {
			log.Info("Skipping agent with missing addresses", "agent", agent.Name)
			continue
		}

		nve, err := netip.ParseAddr(agent.PrivateAddress)
		if err != nil {
			log.Error(err, "Failed to parse private address",
				"agent", agent.Name, "privateAddress", agent.PrivateAddress)
			continue
		}

		agentAddr, err := netip.ParsePrefix(agent.AgentAddress)
		if err != nil {
			log.Error(err, "Failed to parse agent address",
				"agent", agent.Name, "agentAddress", agent.AgentAddress)
			continue
		}
		if !agentAddr.Addr().Is6() || !agentAddr.Addr().IsGlobalUnicast() {
			log.Error(goerrors.New("overlay address must be global unicase IPv6"),
				"Invalid overlay address",
				"agent", agent.Name, "agentAddress", agent.AgentAddress)
			continue
		}
		if agentAddr.Bits() != 96 {
			log.Error(goerrors.New("overlay address must be /96"),
				"Invalid overlay address",
				"agent", agent.Name, "agentAddress", agent.AgentAddress)
			continue
		}
		agentULA, err := tunnet.ULAFromPrefix(ctx, agentAddr)
		if err != nil {
			log.Error(err, "Failed to generate ULA",
				"agent", agent.Name, "agentAddress", agent.AgentAddress)
			continue
		}

		if err := r.routeAdd(ctx, agentULA, nve); err != nil {
			log.Error(err, "Failed to ensure route",
				"agent", agent.Name, "ula", agentAddr.String(), "vne", nve)
			continue
		}

		updRoutes.Insert(agentAddr)
	}

	for _, dst := range curRoutes.Difference(updRoutes).UnsortedList() {
		if err := r.deleteRoute(ctx, dst); err != nil {
			log.Error(err, "Failed to delete stale route", "dst", dst)
			continue
		}
		log.Info("Deleted stale route", "dst", dst)
	}

	return ctrl.Result{}, nil
}

// ensureDevice creates the Geneve link if it doesn't exist.
func (r *TunnelNodeReconciler) ensureDevice(ctx context.Context, ula *tunnet.NetULA) error {
	log := clog.FromContext(ctx)

	link, err := netlink.LinkByName(r.gnvDev)
	if err == nil {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to bring up Geneve interface: %w", err)
		}
		return nil
	}

	log.Info("Creating Geneve interface", "dev", r.gnvDev)

	// Create Geneve interface without a specific remote -
	// this allows us to route to multiple remotes using Linux's
	// lwtunnel infrastructure (https://github.com/torvalds/linux/blob/e347810e84094078d155663acbf36d82efe91f95/net/core/lwtunnel.c).
	geneve := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         r.gnvDev,
			MTU:          r.gnvMTU,
			HardwareAddr: r.hwAddr(ula),
		},
		// No ID and Remote set - this creates an "external" Geneve device.
		FlowBased: true, // external
	}

	if err := netlink.LinkAdd(geneve); err != nil {
		return fmt.Errorf("failed to add Geneve interface: %w", err)
	}

	if err := netlink.LinkSetUp(geneve); err != nil {
		return fmt.Errorf("failed to bring up Geneve interface: %w", err)
	}

	log.Info("Successfully created Geneve interface", "dev", r.gnvDev)

	if err := r.setAddr(ctx, geneve, ula); err != nil {
		return fmt.Errorf("failed to configure device address: %w", err)
	}

	return nil
}

// setAddr adds an IPv6 address to the Geneve interface.
func (r *TunnelNodeReconciler) setAddr(ctx context.Context, link netlink.Link, ula *tunnet.NetULA) error {
	log := clog.FromContext(ctx)

	addr, err := netlink.ParseAddr(ula.FullPrefix().String())
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}

	af := netlink.FAMILY_V6
	if addr.IP.To4() != nil {
		af = netlink.FAMILY_V4
	}
	addrs, err := netlink.AddrList(link, af)
	if err != nil {
		return fmt.Errorf("failed to list addresses: %w", err)
	}
	for _, existing := range addrs {
		if existing.Equal(*addr) {
			log.Info("IPv6 address already configured", "addr", existing)
			return nil
		}
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IPv6 address: %w", err)
	}

	log.Info("Successfully configured IPv6 address", "addr", addr)

	return nil
}

// cleanupGeneve removes the Geneve interface.
func (r *TunnelNodeReconciler) cleanupGeneve(ctx context.Context) error {
	log := clog.FromContext(ctx)

	link, err := netlink.LinkByName(r.gnvDev)
	if err != nil {
		// Interface doesn't exist, nothing to do.
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete Geneve interface: %w", err)
	}

	log.Info("Successfully deleted Geneve interface", "dev", r.gnvDev)

	return nil
}

// routeAdd adds a route to the overlay addr via NVE.
func (r *TunnelNodeReconciler) routeAdd(ctx context.Context, ula *tunnet.NetULA, nve netip.Addr) error {
	log := clog.FromContext(ctx)

	link, err := netlink.LinkByName(r.gnvDev)
	if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	// Create a /96 route for the overlay IPv6 prefix which tells the kernel:
	// "to reach this overlay IP, encapsulate and send to this VTEP"
	// This is equivalent to the following iproute2 command:
	// ip route add <overlayIP>/96 encap ip id <gnvVNI> dst <nve> dev <gnvDev>
	ulaAddr := ula.FullPrefix().Addr()
	af, mask := netlink.FAMILY_V6, 128
	if ulaAddr.Is4() {
		af, mask = netlink.FAMILY_V4, 32
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Family:    af,
		Dst: &net.IPNet{
			IP:   ulaAddr.AsSlice(),
			Mask: net.CIDRMask(ula.FullPrefix().Bits(), mask),
		},
		Encap: &IPEncap{
			ID:     r.gnvVNI,
			Remote: nve.AsSlice(),
		},
		Scope:    netlink.SCOPE_UNIVERSE,
		Protocol: rtProtocol,
	}

	if err := netlink.RouteAdd(route); err != nil {
		if strings.Contains(err.Error(), "exists") {
			if err := netlink.RouteReplace(route); err != nil {
				return fmt.Errorf("failed to replace route: %w", err)
			}
		} else {
			return fmt.Errorf("failed to add route: %w", err)
		}
	}

	log.Info("Configured route", "af", af, "dst", ula, "encap_id",
		r.gnvVNI, "encap_remote", nve.String())

	hwAddr := r.hwAddr(ula)
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           ulaAddr.AsSlice(),
		HardwareAddr: hwAddr,
	}); err != nil {
		return fmt.Errorf("failed to add neighbor entry: %w", err)
	}

	log.Info("Neighbor entry set", "remote", ulaAddr, "hwAddr", hwAddr)

	// Via is needed so that kernel can use the same dst hwaddr for the entire ula prefix.
	// Can't set via during route creation because the route to gw does not yet exist.
	route.Gw = ulaAddr.AsSlice()
	if err := netlink.RouteChange(route); err != nil {
		return fmt.Errorf("failed to change route with gw %v: %w", route.Gw, err)
	}

	log.Info("Configured route gw",
		"af", af, "dst", ula, "gw", ulaAddr,
		"encap_id", r.gnvVNI, "encap_remote", nve)

	return nil
}

func (r *TunnelNodeReconciler) deleteRoute(ctx context.Context, dst netip.Prefix) error {
	link, err := netlink.LinkByName(r.gnvDev)
	if err != nil {
		return fmt.Errorf("failed to get Geneve interface: %w", err)
	}

	mask := 128
	if dst.Addr().Is4() {
		mask = 32
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   dst.Addr().AsSlice(),
			Mask: net.CIDRMask(dst.Bits(), mask),
		},
	}

	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	return nil
}

// routeList returns the current routes for the Geneve interface.
func (r *TunnelNodeReconciler) routeList(ctx context.Context) (sets.Set[netip.Prefix], error) {
	log := log.FromContext(ctx)

	link, err := netlink.LinkByName(r.gnvDev)
	if err != nil {
		return nil, fmt.Errorf("failed to get Geneve link: %w", err)
	}

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_ALL,
		&netlink.Route{
			Protocol: rtProtocol,
		},
		netlink.RT_FILTER_PROTOCOL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	out := sets.New[netip.Prefix]()
	for _, route := range routes {
		// TODO(dilyevsky): netlink doesn't currently support deserialization of encap type ip.
		//if route.Encap == nil || route.Encap.Type() != nl.LWTUNNEL_ENCAP_IP {
		//	log.Info("Skipping route with no/mismatching encap", "dst", route.Dst, "encap", route.Encap)
		//	continue
		//}

		//encap, ok := route.Encap.(*IPEncap)
		//if !ok {
		//	log.Info("Skipping route with non-Geneve Encap", "dst", route.Dst)
		//	continue
		//}
		if link.Attrs().Index != route.LinkIndex {
			log.V(1).Info("Skipping route with mismatching link index", "dst", route.Dst, "linkIndex", link.Attrs().Index, "routeLinkIndex", route.LinkIndex)
			continue
		}

		var dst netip.Prefix
		bits, _ := route.Dst.Mask.Size()
		if route.Dst.IP.To16() != nil {
			dst = netip.PrefixFrom(
				netip.AddrFrom16([16]byte(route.Dst.IP.To16())),
				bits,
			)
		} else if route.Dst.IP.To4() != nil {
			dst = netip.PrefixFrom(
				netip.AddrFrom4([4]byte(route.Dst.IP.To4())),
				bits,
			)
		}

		log.Info("Route found", "dst", dst)

		out.Insert(dst)
	}

	return out, nil
}

// SetupWithManager sets up the controller with the Controller Manager.
func (r *TunnelNodeReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		//Watches(
		//	&ctrlv1alpha1.Proxy{},
		//	handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		//		return []reconcile.Request{
		//			{
		//				NamespacedName: types.NamespacedName{
		//					Name: r.proxyName + "-" + r.proxyReplicaName,
		//				},
		//			},
		//		}
		//	}),
		//	builder.WithPredicates(namePredicate(r.proxyName)),
		//).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(r)
}
