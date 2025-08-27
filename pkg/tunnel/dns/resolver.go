package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/coredns/coredns/plugin"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
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
	upstreamTimeout = 2 * time.Second
)

var tunResolver = netip.AddrPortFrom(
	netip.AddrFrom4([4]byte{127, 0, 0, 1}),
	8053,
)

// TunnelNodeDNSReconciler reconciles TunnelNode objects and implements CoreDNS plugin.
type TunnelNodeDNSReconciler struct {
	client.Client

	nameCache *haxmap.Map[string, sets.Set[netip.Addr]]
	uuidCache *haxmap.Map[string, sets.Set[netip.Addr]]

	opts options
}

type options struct {
	timeout            time.Duration
	perUpstreamTimeout time.Duration
	maxAnswers         int
}

func defaultOptions() options {
	return options{
		timeout:            5 * time.Second,
		perUpstreamTimeout: 2 * time.Second,
		maxAnswers:         10,
	}
}

type Option func(*options)

// WithTimeout sets the timeout for the DNS resolver.
func WithTimeout(timeout time.Duration) Option {
	return func(o *options) {
		o.timeout = timeout
	}
}

// WithPerUpstreamTimeout sets the timeout for each upstream DNS server.
func WithPerUpstreamTimeout(timeout time.Duration) Option {
	return func(o *options) {
		o.perUpstreamTimeout = timeout
	}
}

// WithMaxAnswers sets the maximum number of answers to return.
func WithMaxAnswers(maxAnswers int) Option {
	return func(o *options) {
		o.maxAnswers = maxAnswers
	}
}

// NewTunnelNodeDNSReconciler creates a new TunnelNodeDNSReconciler.
func NewTunnelNodeDNSReconciler(
	client client.Client,
	opts ...Option,
) *TunnelNodeDNSReconciler {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return &TunnelNodeDNSReconciler{
		Client:    client,
		nameCache: haxmap.New[string, sets.Set[netip.Addr]](),
		uuidCache: haxmap.New[string, sets.Set[netip.Addr]](),
		opts:      o,
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
		if agent.AgentAddress == "" {
			log.V(1).Info("Skipping empty Agent IP address", "agent", agent.Name)
			continue
		}
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
		log.Info("Requesting recursive tunnel resolutions")
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
	// Fisher-Yates shuffle to randomize the order of IPs.
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

func (r *TunnelNodeDNSReconciler) upstreamHostFromAddr(addr netip.Addr) (string, error) {
	if !addr.Is6() {
		return "", errors.New("invalid IP address")
	}

	ipv6Bytes := addr.As16()
	ipv4Bytes := tunResolver.Addr().As4()
	ipv6Bytes[12] = ipv4Bytes[0]
	ipv6Bytes[13] = ipv4Bytes[1]
	ipv6Bytes[14] = ipv4Bytes[2]
	ipv6Bytes[15] = ipv4Bytes[3]

	srvAddr := netip.AddrFrom16(ipv6Bytes)
	return netip.AddrPortFrom(srvAddr, tunResolver.Port()).String(), nil
}

func (r *TunnelNodeDNSReconciler) recursiveResolve(
	ctx context.Context,
	w dns.ResponseWriter,
	req *dns.Msg,
	name string,
	upstreams []netip.Addr,
) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.opts.timeout)
	defer cancel()

	rReq := req.Copy()
	rReq.Question[0].Name = name + "."
	rReq.RecursionDesired = true

	// If original request is for IPv6, convert to IPv4 request for upstream.
	isAAAA := len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeAAAA
	if !isAAAA {
		return dns.RcodeNotImplemented, errors.New("only AAAA queries are supported for recursive resolution")
	}

	// Rewrites request as A for upstream resolver.
	rReq.Question[0].Qtype = dns.TypeA

	var (
		mu  sync.Mutex
		out *dns.Msg
		ans []dns.RR
	)

	g, _ := errgroup.WithContext(ctx)
	client := &dns.Client{
		// TODO(mattward): could go back to UDP when tunnels support UDP.
		Net:     "tcp",
		Dialer:  &net.Dialer{Timeout: r.opts.perUpstreamTimeout},
		Timeout: r.opts.perUpstreamTimeout,
	}

	for _, upstream := range upstreams {
		addr, err := r.upstreamHostFromAddr(upstream)
		if err != nil {
			apoxylog.Debugf("invalid IP address %s", upstream)
			continue
		}

		g.Go(func() error {

			response, _, err := client.ExchangeContext(ctx, rReq, addr)
			if err != nil {
				apoxylog.Debugf("recursive query failed for %s via %s: %v", name, addr, err)
				return err
			}
			response = r.convertIPv4ToIPv6Response(req, response, upstream)
			if response == nil {
				return nil
			}

			mu.Lock()
			defer mu.Unlock()
			if out == nil { // Copy first ever response in its entirety, answers will be replaced later.
				out = &dns.Msg{}
				response.CopyTo(out)
			}
			ans = append(ans, response.Answer...)

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return dns.RcodeServerFailure, err
	}

	if len(ans) == 0 {
		return dns.RcodeNameError, errors.New("no answers")
	}

	// Clamp the answers and shuffle to provide load-balancing.
	if r.opts.maxAnswers > 0 && len(ans) > r.opts.maxAnswers {
		ans = ans[:r.opts.maxAnswers]
	}
	rand.Shuffle(len(ans), func(i, j int) {
		ans[i], ans[j] = ans[j], ans[i]
	})
	out.Answer = ans

	if err := w.WriteMsg(out); err != nil {
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
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
