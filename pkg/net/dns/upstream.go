package dns

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
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
		return mdns.RcodeServerFailure, err
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

// LoadResolvConf loads system resolv.conf and sets the upstreams.
func (u *upstream) LoadResolvConf() error {
	r, err := resolvconf.Get()
	if err != nil {
		return fmt.Errorf("failed to get resolvconf: %v", err)
	}
	u.Upstreams = resolvconf.GetNameservers(r.Content, types.IPv4)
	if len(u.Upstreams) == 0 {
		return fmt.Errorf("no nameservers found in resolvconf")
	}
	log.Infof("Using upstreams: %v", u.Upstreams)
	return nil
}
