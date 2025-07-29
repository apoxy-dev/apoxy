package dns

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/docker/docker/libnetwork/resolvconf"
	"github.com/docker/docker/libnetwork/types"
	mdns "github.com/miekg/dns"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

const (
	upstreamPort = 53
)

// upstream is a plugin that sends queries to a random upstream.
type upstream struct {
	Next              plugin.Handler
	Upstreams         []string
	SearchDomains     []string
	Ndots             int
	BlockNonGlobalIPs bool
}

// Name implements the plugin.Handler interface.
func (u *upstream) Name() string { return "upstream" }

// isULA checks if the given address is a Unique Local Address (ULA).
func isULA(addr netip.Addr) bool {
	ulaRange := netip.MustParsePrefix("fc00::/7")
	if addr.Is6() && ulaRange.Contains(addr) {
		return true
	}
	return false
}

// ServeDNS implements the plugin.Handler interface.
func (u *upstream) ServeDNS(ctx context.Context, w mdns.ResponseWriter, r *mdns.Msg) (int, error) {
	log.Debugf("Upstream.ServeDNS: %v", r.Question)
	if len(u.Upstreams) == 0 {
		log.Debugf("No upstreams, using next")
		return u.Next.ServeDNS(ctx, w, r)
	}

	// Try the original query first
	response, rcode, err := u.queryUpstream(r)
	if err != nil {
		return rcode, err
	}

	// Apply search domain logic based on ndots and search domains
	if len(u.SearchDomains) > 0 && len(r.Question) > 0 {
		originalName := r.Question[0].Name
		dotCount := u.countDots(originalName)

		// Determine search strategy based on ndots
		if dotCount < u.Ndots {
			// Try search domains first, then original name if all fail
			if response.Rcode == mdns.RcodeNameError {
				log.Debugf("Name has %d dots (< ndots=%d), trying search domains first: %s", dotCount, u.Ndots, originalName)
				response = u.trySearchDomains(r, originalName, response)
			}
		} else {
			// Try original name first (already done), then search domains if it failed
			if response.Rcode == mdns.RcodeNameError {
				log.Debugf("Name has %d dots (>= ndots=%d), trying search domains after original: %s", dotCount, u.Ndots, originalName)
				response = u.trySearchDomains(r, originalName, response)
			}
		}
	}

	// Block responses referencing non-global unicast IPs if enabled
	if u.BlockNonGlobalIPs {
		for _, answer := range response.Answer {
			if a, ok := answer.(*mdns.A); ok {
				ip := a.A
				if u.BlockNonGlobalIPs && (!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback()) {
					log.Warnf("Answer contains non-global unicast IP: %v, returning NXDOMAIN", ip)
					response.Rcode = mdns.RcodeNameError // NXDOMAIN
					break
				}
			} else if aaaa, ok := answer.(*mdns.AAAA); ok {
				ip := aaaa.AAAA
				ipAddr, _ := netip.AddrFromSlice(ip)
				if u.BlockNonGlobalIPs && (!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || isULA(ipAddr)) {
					log.Warnf("Answer contains non-global unicast IPv6: %v, returning NXDOMAIN", ip)
					response.Rcode = mdns.RcodeNameError // NXDOMAIN
					break
				}
			}
		}
	}

	w.WriteMsg(response)
	return mdns.RcodeSuccess, nil
}

// queryUpstream sends a DNS query to a random upstream server.
func (u *upstream) queryUpstream(r *mdns.Msg) (*mdns.Msg, int, error) {
	upstream := u.Upstreams[rand.Intn(len(u.Upstreams))]

	log.Debugf("Using upstream %v:%d", upstream, upstreamPort)

	client := &mdns.Client{}
	client.Dialer = &net.Dialer{
		Timeout: 2 * time.Second,
	}
	r.RecursionDesired = true

	response, _, err := client.Exchange(r, fmt.Sprintf("%v:%d", upstream, upstreamPort))
	if err != nil {
		log.Debugf("Failed to exchange: %v", err)
		return nil, mdns.RcodeServerFailure, err
	}

	return response, mdns.RcodeSuccess, nil
}

// countDots counts the number of dots in a domain name (excluding the trailing dot).
func (u *upstream) countDots(name string) int {
	// Remove trailing dot if present
	name = strings.TrimSuffix(name, ".")
	return strings.Count(name, ".")
}

// trySearchDomains attempts to resolve a name using configured search domains.
func (u *upstream) trySearchDomains(originalQuery *mdns.Msg, originalName string, fallbackResponse *mdns.Msg) *mdns.Msg {
	for _, domain := range u.SearchDomains {
		// Create a new query with the search domain appended
		searchQuery := originalQuery.Copy()
		searchName := strings.TrimSuffix(originalName, ".") + "." + domain + "."
		searchQuery.Question[0].Name = searchName

		log.Debugf("Trying search domain query: %s", searchName)
		searchResponse, _, searchErr := u.queryUpstream(searchQuery)
		if searchErr != nil {
			continue // Try next search domain
		}

		// If we got a successful response, use it
		if searchResponse.Rcode == mdns.RcodeSuccess {
			log.Debugf("Search domain query succeeded with domain: %s", domain)
			// Rewrite the response to use the original query name
			for _, answer := range searchResponse.Answer {
				answer.Header().Name = originalName
			}
			for _, ns := range searchResponse.Ns {
				ns.Header().Name = originalName
			}
			for _, extra := range searchResponse.Extra {
				extra.Header().Name = originalName
			}
			return searchResponse
		}
	}
	// If no search domain worked, return the original response
	return fallbackResponse
}

// isQualifiedName checks if a domain name is qualified (contains dots other than the trailing dot).
// According to DNS search domain behavior, search domains are only applied to unqualified names.
func (u *upstream) isQualifiedName(name string) bool {
	// Remove trailing dot if present
	name = strings.TrimSuffix(name, ".")
	// A qualified name contains at least one dot
	return strings.Contains(name, ".")
}

// parseNdots parses the ndots value from resolv.conf options.
// If multiple ndots options are present, the last one is used.
func (u *upstream) parseNdots(options []string) int {
	ndots := 1 // Default ndots value
	for _, option := range options {
		if strings.HasPrefix(option, "ndots:") {
			ndotsStr := strings.TrimPrefix(option, "ndots:")
			if parsedNdots, err := strconv.Atoi(ndotsStr); err == nil && parsedNdots >= 0 {
				ndots = parsedNdots
			}
		}
	}
	return ndots
}

// LoadResolvConf loads system resolv.conf and sets the upstreams, search domains, and ndots.
func (u *upstream) LoadResolvConf() error {
	r, err := resolvconf.Get()
	if err != nil {
		return fmt.Errorf("failed to get resolvconf: %v", err)
	}
	u.Upstreams = resolvconf.GetNameservers(r.Content, types.IPv4)
	if len(u.Upstreams) == 0 {
		return fmt.Errorf("no nameservers found in resolvconf")
	}
	u.SearchDomains = resolvconf.GetSearchDomains(r.Content)
	options := resolvconf.GetOptions(r.Content)
	u.Ndots = u.parseNdots(options)
	log.Infof("Using upstreams: %v", u.Upstreams)
	log.Infof("Using search domains: %v", u.SearchDomains)
	log.Infof("Using ndots: %d", u.Ndots)
	return nil
}
