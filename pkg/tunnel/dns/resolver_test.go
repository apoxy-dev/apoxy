package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"

	cdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// testResponseWriter is a mock implementation of the dns.ResponseWriter interface.
type testResponseWriter struct {
	msg *cdns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345))
}
func (w *testResponseWriter) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345))
}
func (w *testResponseWriter) WriteMsg(msg *cdns.Msg) error {
	w.msg = msg
	return nil
}
func (w *testResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testResponseWriter) Close() error              { return nil }
func (w *testResponseWriter) TsigStatus() error         { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)       {}
func (w *testResponseWriter) Hijack()                   {}

// nextHandler is a mock implementation of the plugin.Handler interface.
type nextHandler struct {
	called bool
	code   int
	err    error
}

func (h *nextHandler) Name() string {
	return "nextHandler"
}

func (h *nextHandler) ServeDNS(ctx context.Context, w cdns.ResponseWriter, r *cdns.Msg) (int, error) {
	h.called = true
	return h.code, h.err
}

func TestTunnelNodeDNSReconciler(t *testing.T) {
	// Create a mock TunnelNode
	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
		Status: corev1alpha.TunnelNodeStatus{
			Agents: []corev1alpha.AgentStatus{
				{
					Name:           "agent1",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "fd00::1",
					AgentAddress:   "192.168.1.100",
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	err := corev1alpha.Install(scheme)
	require.NoError(t, err)

	// Create a fake client with the TunnelNode
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	// Create a reconciler
	reconciler := NewTunnelNodeDNSReconciler(client)

	// Test the reconcile logic
	t.Run("Reconcile", func(t *testing.T) {
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: "test-node",
			},
		}

		// Reconcile the resource.
		result, err := reconciler.reconcile(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify the cache was updated
		addr, ok := reconciler.nameCache.Get("test-node")
		require.True(t, ok)
		expectedAddrs := sets.New(netip.MustParseAddr("fd00::1"))
		assert.Equal(t, expectedAddrs, addr)

		// Test handling of non-existent resources.
		req = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: "non-existent",
			},
		}

		// Add a dummy entry to the cache.
		reconciler.nameCache.Set("non-existent", sets.New(netip.MustParseAddr("fd00::2")))

		// Reconcile the non-existent resource.
		result, err = reconciler.reconcile(context.Background(), req)
		assert.NoError(t, err) // Should handle not found gracefully
		assert.Equal(t, ctrl.Result{}, result)
	})
}

func TestTunnelNodeDNSServer(t *testing.T) {
	// Create a mock TunnelNode
	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
		Status: corev1alpha.TunnelNodeStatus{
			Agents: []corev1alpha.AgentStatus{
				{
					Name:           "agent1",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "fd00::1",
					AgentAddress:   "192.168.1.100",
				},
				{
					Name:           "agent3",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "10.0.0.1",
					AgentAddress:   "192.168.1.102",
				},
			},
		},
	}

	// Create a fake client with the TunnelNode
	scheme := runtime.NewScheme()
	err := corev1alpha.Install(scheme)
	require.NoError(t, err)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	// Create a resolver
	resolver := NewTunnelNodeDNSReconciler(client)

	// Add the TunnelNode to the cache
	resolver.nameCache.Set(tunnelNode.Name, sets.New(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.1")))

	// Test the ServeDNS method
	t.Run("ServeDNS - valid IPv6 query", func(t *testing.T) {
		// Create a DNS message
		msg := new(cdns.Msg)
		msg.SetQuestion("test-node.tun.apoxy.net.", cdns.TypeAAAA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)

		// Verify the response
		require.NotNil(t, rw.msg)
		require.Len(t, rw.msg.Answer, 1)
		aaaa, ok := rw.msg.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Answer should be AAAA record")
		expectedIP := netip.MustParseAddr("fd00::1").String()
		assert.Equal(t, expectedIP, aaaa.AAAA.String())
	})

	t.Run("ServeDNS - valid IPv4 query", func(t *testing.T) {
		// Create a DNS message
		msg := new(cdns.Msg)
		msg.SetQuestion("test-node.tun.apoxy.net.", cdns.TypeA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)

		// Verify the response
		require.NotNil(t, rw.msg)
		require.Len(t, rw.msg.Answer, 1)
		a, ok := rw.msg.Answer[0].(*cdns.A)
		require.True(t, ok, "Answer should be A record")
		expectedIP := netip.MustParseAddr("10.0.0.1").String()
		assert.Equal(t, expectedIP, a.A.String())
	})

	t.Run("ServeDNS - non-matching domain", func(t *testing.T) {
		next := &nextHandler{code: cdns.RcodeSuccess}
		handler := resolver.Resolver(next)

		// Create a DNS message
		msg := new(cdns.Msg)
		msg.SetQuestion("example.com.", cdns.TypeA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := handler.ServeDNS(context.Background(), rw, msg)
		require.NoError(t, err)
		assert.Equal(t, 0, code) // Should be handled by the next plugin
	})

	// Test the Resolver function
	t.Run("Resolver", func(t *testing.T) {
		next := &nextHandler{code: cdns.RcodeSuccess}
		handler := resolver.Resolver(next)

		// Create a DNS message for a non-existent agent
		msg := new(cdns.Msg)
		msg.SetQuestion("non-existent.test-node.tun.apoxy.net.", cdns.TypeA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := handler.ServeDNS(context.Background(), rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)
		assert.True(t, next.called, "Next handler should be called")
	})
}

func TestTunnelNodeDNSReconciler_convertIPv4ToIPv6Response(t *testing.T) {
	// Create a reconciler instance for testing
	r := &TunnelNodeDNSReconciler{}

	// IPv4-in-IPv6 mapping base address (::ffff:0:0/96)
	baseIP := netip.MustParseAddr("::ffff:0:0")

	t.Run("converts single A record to AAAA record", func(t *testing.T) {
		// Create original IPv6 AAAA request
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("example.com"), cdns.TypeAAAA)

		// Create IPv4 response with A record
		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Authoritative = true
		ipv4Response.RecursionAvailable = true
		ipv4Response.Rcode = cdns.RcodeSuccess

		// Add A record for 192.168.1.1
		aRecord := &cdns.A{
			Hdr: cdns.RR_Header{
				Name:   "example.com.",
				Rrtype: cdns.TypeA,
				Class:  cdns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.168.1.1").To4(),
		}
		ipv4Response.Answer = append(ipv4Response.Answer, aRecord)

		// Convert to IPv6 response
		ipv6Response := r.convertIPv4ToIPv6Response(originalReq, ipv4Response, baseIP)

		// Verify response structure
		require.NotNil(t, ipv6Response)
		assert.Equal(t, originalReq.Id, ipv6Response.Id)
		assert.True(t, ipv6Response.Response)
		assert.Equal(t, ipv4Response.Authoritative, ipv6Response.Authoritative)
		assert.Equal(t, ipv4Response.RecursionAvailable, ipv6Response.RecursionAvailable)
		assert.Equal(t, int(ipv4Response.Rcode), int(ipv6Response.Rcode))

		// Verify AAAA record conversion
		require.Len(t, ipv6Response.Answer, 1)
		aaaa, ok := ipv6Response.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Expected AAAA record")
		assert.Equal(t, "example.com.", aaaa.Hdr.Name)
		assert.Equal(t, cdns.TypeAAAA, aaaa.Hdr.Rrtype)
		assert.Equal(t, uint16(cdns.ClassINET), aaaa.Hdr.Class)
		assert.Equal(t, uint32(300), aaaa.Hdr.Ttl)

		// Verify IPv6 address mapping (::ffff:192.168.1.1)
		expectedIPv6 := netip.MustParseAddr("::ffff:192.168.1.1")
		actualIPv6 := netip.AddrFrom16([16]byte(aaaa.AAAA))
		assert.Equal(t, expectedIPv6, actualIPv6)
	})

	t.Run("converts multiple A records to AAAA records", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("multi.example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeSuccess

		// Add multiple A records
		addresses := []string{"10.0.0.1", "10.0.0.2", "203.0.113.1"}
		for i, addr := range addresses {
			aRecord := &cdns.A{
				Hdr: cdns.RR_Header{
					Name:   "multi.example.com.",
					Rrtype: cdns.TypeA,
					Class:  cdns.ClassINET,
					Ttl:    uint32(600 + i*100),
				},
				A: net.ParseIP(addr).To4(),
			}
			ipv4Response.Answer = append(ipv4Response.Answer, aRecord)
		}

		ipv6Response := r.convertIPv4ToIPv6Response(originalReq, ipv4Response, baseIP)

		require.NotNil(t, ipv6Response)
		require.Len(t, ipv6Response.Answer, 3)

		// Verify each converted record
		expectedIPv6s := []string{"::ffff:10.0.0.1", "::ffff:10.0.0.2", "::ffff:203.0.113.1"}
		for i, expectedAddr := range expectedIPv6s {
			aaaa, ok := ipv6Response.Answer[i].(*cdns.AAAA)
			require.True(t, ok, "Expected AAAA record at index %d", i)
			assert.Equal(t, "multi.example.com.", aaaa.Hdr.Name)
			assert.Equal(t, cdns.TypeAAAA, aaaa.Hdr.Rrtype)
			assert.Equal(t, uint32(600+i*100), aaaa.Hdr.Ttl)

			actualIPv6 := netip.AddrFrom16([16]byte(aaaa.AAAA))
			expectedIPv6 := netip.MustParseAddr(expectedAddr)
			assert.Equal(t, expectedIPv6, actualIPv6)
		}
	})

	t.Run("preserves non-A records unchanged", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("mixed.example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeSuccess

		// Add A record
		aRecord := &cdns.A{
			Hdr: cdns.RR_Header{
				Name:   "mixed.example.com.",
				Rrtype: cdns.TypeA,
				Class:  cdns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.168.1.1").To4(),
		}

		// Add CNAME record
		cnameRecord := &cdns.CNAME{
			Hdr: cdns.RR_Header{
				Name:   "alias.example.com.",
				Rrtype: cdns.TypeCNAME,
				Class:  cdns.ClassINET,
				Ttl:    600,
			},
			Target: "mixed.example.com.",
		}

		// Add TXT record
		txtRecord := &cdns.TXT{
			Hdr: cdns.RR_Header{
				Name:   "mixed.example.com.",
				Rrtype: cdns.TypeTXT,
				Class:  cdns.ClassINET,
				Ttl:    900,
			},
			Txt: []string{"v=spf1 include:_spf.example.com ~all"},
		}

		ipv4Response.Answer = append(ipv4Response.Answer, aRecord, cnameRecord, txtRecord)

		ipv6Response := r.convertIPv4ToIPv6Response(originalReq, ipv4Response, baseIP)

		require.NotNil(t, ipv6Response)
		require.Len(t, ipv6Response.Answer, 3)

		// First record should be converted AAAA
		aaaa, ok := ipv6Response.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Expected AAAA record")
		assert.Equal(t, "mixed.example.com.", aaaa.Hdr.Name)
		assert.Equal(t, cdns.TypeAAAA, aaaa.Hdr.Rrtype)

		// Second record should be unchanged CNAME
		cname, ok := ipv6Response.Answer[1].(*cdns.CNAME)
		require.True(t, ok, "Expected CNAME record")
		assert.Equal(t, "alias.example.com.", cname.Hdr.Name)
		assert.Equal(t, cdns.TypeCNAME, cname.Hdr.Rrtype)
		assert.Equal(t, "mixed.example.com.", cname.Target)

		// Third record should be unchanged TXT
		txt, ok := ipv6Response.Answer[2].(*cdns.TXT)
		require.True(t, ok, "Expected TXT record")
		assert.Equal(t, "mixed.example.com.", txt.Hdr.Name)
		assert.Equal(t, cdns.TypeTXT, txt.Hdr.Rrtype)
		assert.Equal(t, []string{"v=spf1 include:_spf.example.com ~all"}, txt.Txt)
	})

	t.Run("preserves NS and Extra sections", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeSuccess

		// Add A record
		aRecord := &cdns.A{
			Hdr: cdns.RR_Header{
				Name:   "example.com.",
				Rrtype: cdns.TypeA,
				Class:  cdns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.168.1.1").To4(),
		}
		ipv4Response.Answer = append(ipv4Response.Answer, aRecord)

		// Add NS record
		nsRecord := &cdns.NS{
			Hdr: cdns.RR_Header{
				Name:   "example.com.",
				Rrtype: cdns.TypeNS,
				Class:  cdns.ClassINET,
				Ttl:    86400,
			},
			Ns: "ns1.example.com.",
		}
		ipv4Response.Ns = append(ipv4Response.Ns, nsRecord)

		// Add additional A record for NS
		additionalA := &cdns.A{
			Hdr: cdns.RR_Header{
				Name:   "ns1.example.com.",
				Rrtype: cdns.TypeA,
				Class:  cdns.ClassINET,
				Ttl:    86400,
			},
			A: net.ParseIP("203.0.113.1").To4(),
		}
		ipv4Response.Extra = append(ipv4Response.Extra, additionalA)

		ipv6Response := r.convertIPv4ToIPv6Response(originalReq, ipv4Response, baseIP)

		require.NotNil(t, ipv6Response)
		
		// Verify NS section is preserved
		require.Len(t, ipv6Response.Ns, 1)
		ns, ok := ipv6Response.Ns[0].(*cdns.NS)
		require.True(t, ok)
		assert.Equal(t, "example.com.", ns.Hdr.Name)
		assert.Equal(t, "ns1.example.com.", ns.Ns)

		// Verify Extra section is preserved
		require.Len(t, ipv6Response.Extra, 1)
		extraA, ok := ipv6Response.Extra[0].(*cdns.A)
		require.True(t, ok)
		assert.Equal(t, "ns1.example.com.", extraA.Hdr.Name)
		assert.Equal(t, net.ParseIP("203.0.113.1").To4(), extraA.A)
	})

	t.Run("returns nil for nil response", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("example.com"), cdns.TypeAAAA)

		ipv6Response := r.convertIPv4ToIPv6Response(originalReq, nil, baseIP)
		assert.Nil(t, ipv6Response)
	})

	t.Run("returns nil for empty answer section", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeSuccess
		// No answer records

		ipv6Response := r.convertIPv4ToIPv6Response(originalReq, ipv4Response, baseIP)
		assert.Nil(t, ipv6Response)
	})

	t.Run("handles different IPv4 addresses correctly", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("test.example.com"), cdns.TypeAAAA)

		testCases := []struct {
			name     string
			ipv4Addr string
			expected string
		}{
			{"localhost", "127.0.0.1", "::ffff:127.0.0.1"},
			{"private_10", "10.0.0.1", "::ffff:10.0.0.1"},
			{"private_172", "172.16.0.1", "::ffff:172.16.0.1"},
			{"private_192", "192.168.0.1", "::ffff:192.168.0.1"},
			{"public", "8.8.8.8", "::ffff:8.8.8.8"},
			{"edge_case_0", "0.0.0.0", "::ffff:0.0.0.0"},
			{"edge_case_255", "255.255.255.255", "::ffff:255.255.255.255"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ipv4Response := new(cdns.Msg)
				ipv4Response.SetReply(originalReq)
				ipv4Response.Rcode = cdns.RcodeSuccess

				aRecord := &cdns.A{
					Hdr: cdns.RR_Header{
						Name:   "test.example.com.",
						Rrtype: cdns.TypeA,
						Class:  cdns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP(tc.ipv4Addr).To4(),
				}
				ipv4Response.Answer = append(ipv4Response.Answer, aRecord)

				ipv6Response := r.convertIPv4ToIPv6Response(originalReq, ipv4Response, baseIP)

				require.NotNil(t, ipv6Response)
				require.Len(t, ipv6Response.Answer, 1)

				aaaa, ok := ipv6Response.Answer[0].(*cdns.AAAA)
				require.True(t, ok)

				actualIPv6 := netip.AddrFrom16([16]byte(aaaa.AAAA))
				expectedIPv6 := netip.MustParseAddr(tc.expected)
				assert.Equal(t, expectedIPv6, actualIPv6, "IPv4 %s should map to IPv6 %s", tc.ipv4Addr, tc.expected)
			})
		}
	})

	t.Run("preserves error response codes", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("nonexistent.example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeNameError
		ipv4Response.Authoritative = true
		ipv4Response.RecursionAvailable = false

		// Add a dummy A record to ensure it's not the empty answer check
		aRecord := &cdns.A{
			Hdr: cdns.RR_Header{
				Name:   "nonexistent.example.com.",
				Rrtype: cdns.TypeA,
				Class:  cdns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.168.1.1").To4(),
		}
		ipv4Response.Answer = append(ipv4Response.Answer, aRecord)

		ipv6Response := r.convertIPv4ToIPv6Response(originalReq, ipv4Response, baseIP)

		require.NotNil(t, ipv6Response)
		assert.Equal(t, int(cdns.RcodeNameError), int(ipv6Response.Rcode))
		assert.True(t, ipv6Response.Authoritative)
		assert.False(t, ipv6Response.RecursionAvailable)
	})
}
