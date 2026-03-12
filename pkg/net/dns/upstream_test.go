package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// queryLog records the FQDNs queried in order.
type queryLog struct {
	mu      sync.Mutex
	queries []string
}

func (l *queryLog) append(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queries = append(l.queries, name)
}

func (l *queryLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.queries))
	copy(out, l.queries)
	return out
}

// fakeUpstreamServer starts a local DNS server that answers queries based on
// a set of known names. Unknown names get NXDOMAIN.
type fakeUpstreamServer struct {
	addr     string
	known    map[string]string // FQDN -> IP answer (A record)
	log      *queryLog
	server   *mdns.Server
	udpConn  net.PacketConn
}

func newFakeUpstream(t *testing.T, known map[string]string, log *queryLog) *fakeUpstreamServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	f := &fakeUpstreamServer{
		addr:    pc.LocalAddr().String(),
		known:   known,
		log:     log,
		udpConn: pc,
	}
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", f.handler)
	f.server = &mdns.Server{
		PacketConn: pc,
		Handler:    mux,
	}
	go func() { _ = f.server.ActivateAndServe() }()
	return f
}

func (f *fakeUpstreamServer) handler(w mdns.ResponseWriter, r *mdns.Msg) {
	q := r.Question[0]
	f.log.append(q.Name)

	resp := new(mdns.Msg)
	resp.SetReply(r)

	if ip, ok := f.known[q.Name]; ok && q.Qtype == mdns.TypeA {
		resp.Answer = append(resp.Answer, &mdns.A{
			Hdr: mdns.RR_Header{
				Name:   q.Name,
				Rrtype: mdns.TypeA,
				Class:  mdns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP(ip),
		})
	} else {
		resp.Rcode = mdns.RcodeNameError
	}
	w.WriteMsg(resp)
}

func (f *fakeUpstreamServer) close() {
	f.server.Shutdown()
	f.udpConn.Close()
}

// upstreamPort returns just the port number so we can override the upstream
// client to hit it.
func (f *fakeUpstreamServer) port() string {
	_, port, _ := net.SplitHostPort(f.addr)
	return port
}

// serveDNSHelper builds an upstream, sends a query, and returns the response.
func serveDNSHelper(t *testing.T, u *upstream, name string, qtype uint16) *mdns.Msg {
	t.Helper()
	r := new(mdns.Msg)
	r.SetQuestion(mdns.Fqdn(name), qtype)

	rec := &dnsRecorder{}
	_, err := u.ServeDNS(context.Background(), rec, r)
	require.NoError(t, err)
	require.NotNil(t, rec.msg, "expected a DNS response")
	return rec.msg
}

// dnsRecorder captures the response written via WriteMsg.
type dnsRecorder struct {
	msg *mdns.Msg
}

func (r *dnsRecorder) WriteMsg(m *mdns.Msg) error { r.msg = m; return nil }
func (r *dnsRecorder) LocalAddr() net.Addr         { return nil }
func (r *dnsRecorder) RemoteAddr() net.Addr         { return nil }
func (r *dnsRecorder) Write([]byte) (int, error)    { return 0, fmt.Errorf("not implemented") }
func (r *dnsRecorder) Close() error                 { return nil }
func (r *dnsRecorder) TsigStatus() error            { return nil }
func (r *dnsRecorder) TsigTimersOnly(bool)          {}
func (r *dnsRecorder) Hijack()                      {}

func TestServeDNS_NdotsSearchDomainPriority(t *testing.T) {
	tests := []struct {
		name           string
		queryName      string // domain to query
		ndots          int
		searchDomains  []string
		knownNames     map[string]string // FQDN->IP that the fake upstream knows
		wantRcode      int
		wantAnswer     string // expected IP in answer, "" if NXDOMAIN expected
		wantFirstQuery string // first FQDN the upstream should have received
	}{
		{
			name:          "dotCount < ndots: search domains tried first",
			queryName:     "apache.default",
			ndots:         5,
			searchDomains: []string{"svc.cluster.local", "cluster.local"},
			knownNames: map[string]string{
				"apache.default.svc.cluster.local.": "10.0.0.1",
			},
			wantRcode:      mdns.RcodeSuccess,
			wantAnswer:     "10.0.0.1",
			wantFirstQuery: "apache.default.svc.cluster.local.",
		},
		{
			name:          "dotCount >= ndots: bare name tried first",
			queryName:     "api.example.com",
			ndots:         2,
			searchDomains: []string{"svc.cluster.local"},
			knownNames: map[string]string{
				"api.example.com.": "1.2.3.4",
			},
			wantRcode:      mdns.RcodeSuccess,
			wantAnswer:     "1.2.3.4",
			wantFirstQuery: "api.example.com.",
		},
		{
			name:          "dotCount >= ndots: bare fails, falls back to search domain",
			queryName:     "api.example.com",
			ndots:         2,
			searchDomains: []string{"svc.cluster.local"},
			knownNames: map[string]string{
				"api.example.com.svc.cluster.local.": "10.0.0.2",
			},
			wantRcode:      mdns.RcodeSuccess,
			wantAnswer:     "10.0.0.2",
			wantFirstQuery: "api.example.com.",
		},
		{
			name:          "no search domains: direct upstream query",
			queryName:     "apache.default",
			ndots:         5,
			searchDomains: nil,
			knownNames: map[string]string{
				"apache.default.": "10.0.0.3",
			},
			wantRcode:      mdns.RcodeSuccess,
			wantAnswer:     "10.0.0.3",
			wantFirstQuery: "apache.default.",
		},
		{
			name:          "dotCount < ndots: all search domains fail, falls back to bare name",
			queryName:     "myservice.ns",
			ndots:         5,
			searchDomains: []string{"svc.cluster.local", "cluster.local"},
			knownNames: map[string]string{
				"myservice.ns.": "10.0.0.4",
			},
			wantRcode:      mdns.RcodeSuccess,
			wantAnswer:     "10.0.0.4",
			wantFirstQuery: "myservice.ns.svc.cluster.local.",
		},
		{
			name:          "dotCount < ndots: everything fails returns NXDOMAIN",
			queryName:     "nonexistent.svc",
			ndots:         5,
			searchDomains: []string{"svc.cluster.local"},
			knownNames:    map[string]string{},
			wantRcode:     mdns.RcodeNameError,
			wantAnswer:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &queryLog{}
			fake := newFakeUpstream(t, tt.knownNames, log)
			defer fake.close()

			host, port, err := net.SplitHostPort(fake.addr)
			require.NoError(t, err)

			u := &upstream{
				Upstreams:     []string{host},
				SearchDomains: tt.searchDomains,
				Ndots:         tt.ndots,
			}
			// Override the upstream port for testing.
			origPort := upstreamPort
			defer func() { setUpstreamPort(origPort) }()
			setUpstreamPort(mustAtoi(port))

			resp := serveDNSHelper(t, u, tt.queryName, mdns.TypeA)

			assert.Equal(t, tt.wantRcode, resp.Rcode, "unexpected rcode")

			if tt.wantAnswer != "" {
				require.Len(t, resp.Answer, 1, "expected one answer")
				a, ok := resp.Answer[0].(*mdns.A)
				require.True(t, ok)
				assert.Equal(t, tt.wantAnswer, a.A.String())
			}

			if tt.wantFirstQuery != "" {
				queries := log.list()
				require.NotEmpty(t, queries, "expected at least one upstream query")
				assert.Equal(t, tt.wantFirstQuery, queries[0], "first query mismatch")
			}
		})
	}
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
