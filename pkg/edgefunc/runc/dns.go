//go:build linux

package runc

import (
	"context"
	"errors"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	"github.com/apoxy-dev/apoxy/pkg/edgefunc/runc/network"
	"github.com/apoxy-dev/apoxy/pkg/log"
	apoxynet "github.com/apoxy-dev/apoxy/pkg/net"
)

const (
	resolverName = "edgefunc-resolver"
)

// Resolver implements edgefunc.Runtime.Resolver.
func (r *Runtime) Resolver(next plugin.Handler) plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
		if len(req.Question) == 0 {
			return dns.RcodeSuccess, nil
		}

		qname := req.Question[0].Name
		if !strings.HasSuffix(qname, strings.TrimSuffix(apoxynet.EdgeFuncDomain, ".")+".") {
			log.Debugf("Query name %v does not end with %q", qname, apoxynet.EdgeFuncDomain)
			return plugin.NextOrFailure(resolverName, next, ctx, w, req)
		}

		name := strings.TrimSuffix(qname, apoxynet.EdgeFuncDomain+".")
		name = strings.TrimSuffix(name, ".")
		if name == "" {
			log.Debugf("Empty name from %v", qname)
			return dns.RcodeNameError, nil
		}

		log.Debugf("resolving %v", name)

		s, err := r.net.Status(ctx, name)
		if err != nil {
			log.Debugf("failed to get status for %v: %v", name, err)
			if errors.Is(err, network.ErrSandboxNotFound) {
				msg := new(dns.Msg)
				msg.SetRcode(req, dns.RcodeNameError)
				msg.Authoritative = true
				msg.Ns = []dns.RR{new(dns.NS)}
				msg.Answer = []dns.RR{new(dns.A)}
				w.WriteMsg(msg)
				return dns.RcodeNameError, nil
			}
			return dns.RcodeServerFailure, err
		}

		log.Debugf("found container %v, resolving to %v", name, s.IP)

		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative = true

		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		}
		rr.A = s.IP.AsSlice()

		msg.Answer = append(msg.Answer, rr)
		w.WriteMsg(msg)

		return dns.RcodeSuccess, nil
	})
}
