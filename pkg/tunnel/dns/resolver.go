package dns

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/coredns/coredns/plugin"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	apoxylog "github.com/apoxy-dev/apoxy/pkg/log"
	apoxynet "github.com/apoxy-dev/apoxy/pkg/net"
)

const (
	recursiveResolveTimeout = 10 * time.Second
	upstreamTimeout         = 2 * time.Second
)

// TunnelNodeDNSReconciler reconciles TunnelNode objects and implements CoreDNS plugin.
type TunnelNodeDNSReconciler struct {
	client.Client

	nameCache *haxmap.Map[string, sets.Set[netip.Addr]]
	uuidCache *haxmap.Map[string, sets.Set[netip.Addr]]
}

// NewTunnelNodeDNSReconciler creates a new TunnelNodeDNSReconciler.
func NewTunnelNodeDNSReconciler(client client.Client) *TunnelNodeDNSReconciler {
	return &TunnelNodeDNSReconciler{
		Client:    client,
		nameCache: haxmap.New[string, sets.Set[netip.Addr]](),
		uuidCache: haxmap.New[string, sets.Set[netip.Addr]](),
	}
}

func (r *TunnelNodeDNSReconciler) reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	node := &corev1alpha.TunnelNode{}
	if err := r.Get(ctx, request.NamespacedName, node); apierrors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get TunnelNode: %w", err)
	}

	log := log.FromContext(ctx, "name", node.Name, "uid", node.UID)
	log.Info("Reconciling TunnelNode")

	if !node.DeletionTimestamp.IsZero() {
		r.nameCache.Del(node.Name)
		r.uuidCache.Del(string(node.UID))
		return reconcile.Result{}, nil
	}

	ips := sets.New[netip.Addr]()
	for _, agent := range node.Status.Agents {
		ip, err := netip.ParseAddr(agent.AgentAddress)
		if err != nil {
			log.Error(err, "Invalid Agent IP address", "addr", agent.AgentAddress, "agent", agent.Name)
			continue
		}
		if ips.Has(ip) {
			continue
		}
		ips.Insert(ip)
	}

	r.nameCache.Set(node.Name, ips)
	r.uuidCache.Set(string(node.UID), ips)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TunnelNodeDNSReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(r.name()).
		For(&corev1alpha.TunnelNode{}).
		Complete(reconcile.Func(r.reconcile))
}

func (r *TunnelNodeDNSReconciler) name() string { return "tunnel-resolver" }

func (r *TunnelNodeDNSReconciler) serveDNS(ctx context.Context, next plugin.Handler, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	if len(req.Question) == 0 {
		return dns.RcodeSuccess, nil
	}

	log := slog.With(slog.String("qname", req.Question[0].Name))

	qname := req.Question[0].Name
	if !strings.HasSuffix(qname, strings.TrimSuffix(apoxynet.TunnelDomain, ".")+".") {
		log.Debug("Query name does not match TunnelDomain", slog.String("domain_suffix", apoxynet.TunnelDomain))
		return plugin.NextOrFailure(r.name(), next, ctx, w, req)
	}

	name := strings.TrimSuffix(qname, apoxynet.TunnelDomain+".")
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		log.Warn("Empty name")
		return dns.RcodeNameError, nil
	}
	recursive := ""
	if strings.Contains(name, ".") {
		log.Info(fmt.Sprintf("requesting recursive tunnel resolution of %s", name))
		qp := strings.Split(name, ".")
		recursive = strings.Join(qp[:len(qp)-1], ".")
		name = qp[len(qp)-1]
	}

	var (
		found bool
		ips   sets.Set[netip.Addr]
	)
	nodeUUID, err := uuid.Parse(name)
	if err == nil {
		ips, found = r.uuidCache.Get(nodeUUID.String())
	} else {
		ips, found = r.nameCache.Get(name)
	}
	if !found {
		log.Warn("Node not found")
		return dns.RcodeNameError, nil
	}

	ipSlice := ips.UnsortedList() // returns a slice copy.
	// Fisher-Yates shuffle to randomize the order of IPs
	for i := len(ips) - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		ipSlice[i], ipSlice[j] = ipSlice[j], ipSlice[i]
	}
	if recursive != "" {
		return r.recursiveResolve(ctx, w, req, recursive, ipSlice)
	}

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	for _, ip := range ipSlice {
		var rr dns.RR
		log.Info("Processing IP", slog.String("addr", ip.String()))
		if ip.Is4() && req.Question[0].Qtype == dns.TypeA {
			rr = new(dns.A)
			rr.(*dns.A).Hdr = dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			}
			rr.(*dns.A).A = ip.AsSlice()
		} else if ip.Is6() && req.Question[0].Qtype == dns.TypeAAAA {
			rr = new(dns.AAAA)
			rr.(*dns.AAAA).Hdr = dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    30,
			}
			rr.(*dns.AAAA).AAAA = ip.AsSlice()
		} else {
			log.Warn("Invalid IP address", slog.String("addr", ip.String()))
			continue
		}

		msg.Answer = append(msg.Answer, rr)
	}

	if len(msg.Answer) == 0 {
		log.Warn("No valid IP addresses found")
		return dns.RcodeServerFailure, nil
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Error("Failed to write response", slog.Any("error", err))
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
}

func (r *TunnelNodeDNSReconciler) recursiveResolve(ctx context.Context, w dns.ResponseWriter, req *dns.Msg, name string, ips []netip.Addr) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, recursiveResolveTimeout)
	defer cancel()

	// Check if the original request is for IPv6 addresses only
	isIPv6Request := len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeAAAA

	recursiveReq := req.Copy()
	recursiveReq.Question[0].Name = name + "."
	recursiveReq.RecursionDesired = true

	// If original request is for IPv6, convert to IPv4 request for upstream
	if isIPv6Request {
		recursiveReq.Question[0].Qtype = dns.TypeA
		apoxylog.Debugf("converting IPv6 request to IPv4 for recursive resolution of %s", name)
	}

	var lastErr error
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			apoxylog.Debugf("recursive resolution timeout for %s", name)
			return dns.RcodeServerFailure, fmt.Errorf("recursive resolution timeout")
		default:
		}
		client := &dns.Client{
			Dialer:  &net.Dialer{Timeout: upstreamTimeout},
			Timeout: upstreamTimeout,
		}
		var addr string
		if ip.Is6() {
			ipv6Bytes := ip.As16()
			ipv6Bytes[12] = 127
			ipv6Bytes[13] = 0
			ipv6Bytes[14] = 0
			ipv6Bytes[15] = 53
			targetIP := netip.AddrFrom16(ipv6Bytes)
			addr = fmt.Sprintf("[%s]:8053", targetIP.String())
		} else {
			apoxylog.Debugf("non-IPv6 address %s, skipping", ip.String())
			continue
		}
		apoxylog.Debugf("trying recursive resolution for %s via %s", name, addr)
		response, _, err := client.Exchange(recursiveReq, addr)
		if err != nil {
			apoxylog.Debugf("recursive query failed for %s via %s: %v", name, addr, err)
			lastErr = err
			continue
		}
		if response == nil {
			apoxylog.Debugf("nil response for %s via %s", name, addr)
			lastErr = fmt.Errorf("nil response")
			continue
		}

		if isIPv6Request && response.Rcode == dns.RcodeSuccess {
			convertedResponse := r.convertIPv4ToIPv6Response(req, response, ip)
			if convertedResponse != nil {
				if err := w.WriteMsg(convertedResponse); err != nil {
					return dns.RcodeServerFailure, err
				}
				return dns.RcodeSuccess, nil
			}
		}

		apoxylog.Debugf("successful recursive resolution for %s via %s", name, addr)
		if err := w.WriteMsg(response); err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeSuccess, nil
	}
	if lastErr != nil {
		apoxylog.Errorf("recursive resolution failed for %s: %v", name, lastErr)
		return dns.RcodeServerFailure, fmt.Errorf("recursive resolution failed: %w", lastErr)
	}
	apoxylog.Errorf("recursive resolution failed for %s: no upstreams responded", name)
	return dns.RcodeServerFailure, fmt.Errorf("recursive resolution failed: no upstreams responded")
}

func (r *TunnelNodeDNSReconciler) convertIPv4ToIPv6Response(originalReq *dns.Msg, ipv4Response *dns.Msg, baseIP netip.Addr) *dns.Msg {
	if ipv4Response == nil || len(ipv4Response.Answer) == 0 {
		return nil
	}
	ipv6Response := new(dns.Msg)
	ipv6Response.SetReply(originalReq)
	ipv6Response.Authoritative = ipv4Response.Authoritative
	ipv6Response.RecursionAvailable = ipv4Response.RecursionAvailable
	ipv6Response.Rcode = ipv4Response.Rcode
	baseBytes := baseIP.As16()
	for _, rr := range ipv4Response.Answer {
		if aRecord, ok := rr.(*dns.A); ok {
			var ipv6Bytes [16]byte
			copy(ipv6Bytes[:12], baseBytes[:12])
			copy(ipv6Bytes[12:], aRecord.A)
			ipv6Addr := netip.AddrFrom16(ipv6Bytes)
			aaaa := new(dns.AAAA)
			aaaa.Hdr = dns.RR_Header{
				Name:   aRecord.Hdr.Name,
				Rrtype: dns.TypeAAAA,
				Class:  aRecord.Hdr.Class,
				Ttl:    aRecord.Hdr.Ttl,
			}
			aaaa.AAAA = ipv6Addr.AsSlice()
			ipv6Response.Answer = append(ipv6Response.Answer, aaaa)
		} else {
			ipv6Response.Answer = append(ipv6Response.Answer, rr)
		}
	}
	ipv6Response.Ns = ipv4Response.Ns
	ipv6Response.Extra = ipv4Response.Extra
	return ipv6Response
}

// Resolver returns a plugin.Handler that can be used with the CoreDNS server.
func (r *TunnelNodeDNSReconciler) Resolver(next plugin.Handler) plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
		code, err := r.serveDNS(ctx, next, w, req)
		if code != dns.RcodeSuccess || err != nil {
			return plugin.NextOrFailure(r.name(), next, ctx, w, req)
		}
		return code, err
	})
}
