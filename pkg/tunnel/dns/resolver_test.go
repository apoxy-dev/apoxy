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
	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			UID:  "test-uid-1234",
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
					Name:           "agent2",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "10.0.0.1",
					AgentAddress:   "192.168.1.101",
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	err := corev1alpha.Install(scheme)
	require.NoError(t, err)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	reconciler := NewTunnelNodeDNSReconciler(client)

	t.Run("Reconcile", func(t *testing.T) {
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: "test-node",
			},
		}

		result, err := reconciler.reconcile(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify the cache was updated with correct IPs.
		addr, ok := reconciler.nameCache.Get("test-node")
		require.True(t, ok)
		expectedAddrs := sets.New(netip.MustParseAddr("192.168.1.100"), netip.MustParseAddr("192.168.1.101"))
		assert.Equal(t, expectedAddrs, addr)

		// Verify UUID cache was also updated.
		uuidAddr, ok := reconciler.uuidCache.Get("test-uid-1234")
		require.True(t, ok)
		assert.Equal(t, expectedAddrs, uuidAddr)
	})

	t.Run("Reconcile_NonExistent", func(t *testing.T) {
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: "non-existent",
			},
		}

		reconciler.nameCache.Set("non-existent", sets.New(netip.MustParseAddr("fd00::2")))

		result, err := reconciler.reconcile(context.Background(), req)
		assert.NoError(t, err) // Should handle not found gracefully
		assert.Equal(t, ctrl.Result{}, result)
	})
}

func TestTunnelNodeDNSServer(t *testing.T) {
	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			UID:  "550e8400-e29b-41d4-a716-446655440000",
		},
		Status: corev1alpha.TunnelNodeStatus{
			Agents: []corev1alpha.AgentStatus{
				{
					Name:           "agent1",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "fd00::1",
					AgentAddress:   "fd00::1",
				},
				{
					Name:           "agent3",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "10.0.0.1",
					AgentAddress:   "10.0.0.1",
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	err := corev1alpha.Install(scheme)
	require.NoError(t, err)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	resolver := NewTunnelNodeDNSReconciler(client)

	// Add the TunnelNode to the cache.
	resolver.nameCache.Set(tunnelNode.Name, sets.New(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.1")))
	resolver.uuidCache.Set(string(tunnelNode.UID), sets.New(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.1")))

	t.Run("ServeDNS - valid IPv6 query by name", func(t *testing.T) {
		msg := new(cdns.Msg)
		msg.SetQuestion("test-node.tun.apoxy.net.", cdns.TypeAAAA)

		rw := &testResponseWriter{}

		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)

		require.NotNil(t, rw.msg)
		require.Len(t, rw.msg.Answer, 1)
		aaaa, ok := rw.msg.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Answer should be AAAA record")
		expectedIP := netip.MustParseAddr("fd00::1")
		actualIP := netip.AddrFrom16([16]byte(aaaa.AAAA))
		assert.Equal(t, expectedIP, actualIP)
	})

	t.Run("ServeDNS - valid IPv4 query by name", func(t *testing.T) {
		msg := new(cdns.Msg)
		msg.SetQuestion("test-node.tun.apoxy.net.", cdns.TypeA)

		rw := &testResponseWriter{}

		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)

		require.NotNil(t, rw.msg)
		require.Len(t, rw.msg.Answer, 1)
		a, ok := rw.msg.Answer[0].(*cdns.A)
		require.True(t, ok, "Answer should be A record")
		expectedIP := netip.MustParseAddr("10.0.0.1")
		actualIP := netip.AddrFrom4([4]byte(a.A))
		assert.Equal(t, expectedIP, actualIP)
	})

	t.Run("ServeDNS - valid query by UUID", func(t *testing.T) {
		msg := new(cdns.Msg)
		msg.SetQuestion("550e8400-e29b-41d4-a716-446655440000.tun.apoxy.net.", cdns.TypeAAAA)

		rw := &testResponseWriter{}

		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)

		require.NotNil(t, rw.msg)
		require.Len(t, rw.msg.Answer, 1)
		aaaa, ok := rw.msg.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Answer should be AAAA record")
		expectedIP := netip.MustParseAddr("fd00::1")
		actualIP := netip.AddrFrom16([16]byte(aaaa.AAAA))
		assert.Equal(t, expectedIP, actualIP)
	})

	t.Run("ServeDNS - non-matching domain", func(t *testing.T) {
		next := &nextHandler{code: cdns.RcodeSuccess}
		handler := resolver.Resolver(next)

		msg := new(cdns.Msg)
		msg.SetQuestion("example.com.", cdns.TypeA)

		rw := &testResponseWriter{}

		code, err := handler.ServeDNS(context.Background(), rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code) // Should be handled by the next plugin
		assert.True(t, next.called, "Next handler should be called")
	})

	t.Run("ServeDNS - non-existent node", func(t *testing.T) {
		msg := new(cdns.Msg)
		msg.SetQuestion("non-existent.tun.apoxy.net.", cdns.TypeA)

		rw := &testResponseWriter{}

		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeNameError, code)
	})

	t.Run("ServeDNS - empty question", func(t *testing.T) {
		msg := new(cdns.Msg)

		rw := &testResponseWriter{}

		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)
	})
}

func TestAToAAAA(t *testing.T) {
	t.Run("converts single A record to AAAA record", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Authoritative = true
		ipv4Response.RecursionAvailable = true
		ipv4Response.Rcode = cdns.RcodeSuccess

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

		v6base := netip.MustParseAddr("fd00::1:0:0")

		aToAAAA(originalReq, v6base, ipv4Response)

		require.NotNil(t, ipv4Response)
		assert.True(t, ipv4Response.Response)
		assert.Equal(t, true, ipv4Response.Authoritative)
		assert.Equal(t, true, ipv4Response.RecursionAvailable)
		assert.Equal(t, cdns.RcodeSuccess, ipv4Response.Rcode)

		require.Len(t, ipv4Response.Answer, 1)
		aaaa, ok := ipv4Response.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Expected AAAA record")
		assert.Equal(t, "example.com.", aaaa.Hdr.Name)
		assert.Equal(t, cdns.TypeAAAA, aaaa.Hdr.Rrtype)
		assert.Equal(t, uint16(cdns.ClassINET), aaaa.Hdr.Class)
		assert.Equal(t, uint32(300), aaaa.Hdr.Ttl)

		actualIPv6 := netip.AddrFrom16([16]byte(aaaa.AAAA))
		baseAs16 := v6base.As16()
		actualAs16 := actualIPv6.As16()
		assert.Equal(t, baseAs16[:12], actualAs16[:12], "First 12 bytes should match base IPv6")
		assert.Equal(t, net.ParseIP("192.168.1.1").To4(), aaaa.AAAA[12:], "Last 4 bytes should be IPv4 address")
	})

	t.Run("converts multiple A records to AAAA records", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("multi.example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeSuccess

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

		v6base := netip.MustParseAddr("fd00::1:0:0")

		aToAAAA(originalReq, v6base, ipv4Response)

		require.NotNil(t, ipv4Response)
		require.Len(t, ipv4Response.Answer, 3)

		baseAs16 := v6base.As16()
		for i, addr := range addresses {
			aaaa, ok := ipv4Response.Answer[i].(*cdns.AAAA)
			require.True(t, ok, "Expected AAAA record at index %d", i)
			assert.Equal(t, "multi.example.com.", aaaa.Hdr.Name)
			assert.Equal(t, cdns.TypeAAAA, aaaa.Hdr.Rrtype)
			assert.Equal(t, uint32(600+i*100), aaaa.Hdr.Ttl)

			actualAs16 := [16]byte(aaaa.AAAA)
			assert.Equal(t, baseAs16[:12], actualAs16[:12], "First 12 bytes should match base IPv6")
			assert.Equal(t, net.ParseIP(addr).To4(), aaaa.AAAA[12:], "Last 4 bytes should be IPv4 address")
		}
	})

	t.Run("only converts A records leaving other types unchanged", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("mixed.example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeSuccess

		aRecord := &cdns.A{
			Hdr: cdns.RR_Header{
				Name:   "mixed.example.com.",
				Rrtype: cdns.TypeA,
				Class:  cdns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.168.1.1").To4(),
		}

		cnameRecord := &cdns.CNAME{
			Hdr: cdns.RR_Header{
				Name:   "alias.example.com.",
				Rrtype: cdns.TypeCNAME,
				Class:  cdns.ClassINET,
				Ttl:    600,
			},
			Target: "mixed.example.com.",
		}

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

		v6base := netip.MustParseAddr("fd00::1")

		aToAAAA(originalReq, v6base, ipv4Response)

		require.NotNil(t, ipv4Response)
		require.Len(t, ipv4Response.Answer, 3)

		aaaa, ok := ipv4Response.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Expected AAAA record")
		assert.Equal(t, "mixed.example.com.", aaaa.Hdr.Name)
		assert.Equal(t, cdns.TypeAAAA, aaaa.Hdr.Rrtype)

		cname, ok := ipv4Response.Answer[1].(*cdns.CNAME)
		require.True(t, ok, "Expected CNAME record")
		assert.Equal(t, "alias.example.com.", cname.Hdr.Name)
		assert.Equal(t, cdns.TypeCNAME, cname.Hdr.Rrtype)
		assert.Equal(t, "mixed.example.com.", cname.Target)

		txt, ok := ipv4Response.Answer[2].(*cdns.TXT)
		require.True(t, ok, "Expected TXT record")
		assert.Equal(t, "mixed.example.com.", txt.Hdr.Name)
		assert.Equal(t, cdns.TypeTXT, txt.Hdr.Rrtype)
		assert.Equal(t, []string{"v=spf1 include:_spf.example.com ~all"}, txt.Txt)
	})

	t.Run("handles empty response gracefully", func(t *testing.T) {
		originalReq := new(cdns.Msg)
		originalReq.SetQuestion(cdns.Fqdn("example.com"), cdns.TypeAAAA)

		ipv4Response := new(cdns.Msg)
		ipv4Response.SetReply(originalReq)
		ipv4Response.Rcode = cdns.RcodeSuccess

		v6base := netip.MustParseAddr("fd00::1:0:0")

		aToAAAA(originalReq, v6base, ipv4Response)

		// Response should remain unchanged
		assert.Len(t, ipv4Response.Answer, 0)
	})

	t.Run("handles different IPv4 addresses correctly", func(t *testing.T) {
		testCases := []struct {
			name     string
			ipv4Addr string
			baseIPv6 string
		}{
			{"localhost", "127.0.0.1", "fd00::1"},
			{"private_10", "10.0.0.1", "fd00::2"},
			{"private_172", "172.16.0.1", "fd00::3"},
			{"private_192", "192.168.0.1", "fd00::4"},
			{"public", "8.8.8.8", "fd00::5"},
			{"edge_case_0", "0.0.0.0", "fd00::6"},
			{"edge_case_255", "255.255.255.255", "fd00::7"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				originalReq := new(cdns.Msg)
				originalReq.SetQuestion(cdns.Fqdn("test.example.com"), cdns.TypeAAAA)

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

				baseIP := netip.MustParseAddr(tc.baseIPv6)
				aToAAAA(originalReq, baseIP, ipv4Response)

				require.NotNil(t, ipv4Response)
				require.Len(t, ipv4Response.Answer, 1)

				aaaa, ok := ipv4Response.Answer[0].(*cdns.AAAA)
				require.True(t, ok)

				// Verify the IPv6 address has the correct structure
				actualAs16 := [16]byte(aaaa.AAAA)
				baseAs16 := baseIP.As16()
				assert.Equal(t, baseAs16[:12], actualAs16[:12], "First 12 bytes should match base IPv6")
				assert.Equal(t, net.ParseIP(tc.ipv4Addr).To4(), aaaa.AAAA[12:], "Last 4 bytes should be IPv4 address")
			})
		}
	})
}

func TestUpstreamHostFromAddr(t *testing.T) {
	r := &TunnelNodeDNSReconciler{}

	t.Run("valid IPv6 address", func(t *testing.T) {
		addr := netip.MustParseAddr("fd00::1")
		host, err := r.upstreamHostFromAddr(addr)
		require.NoError(t, err)

		// Should embed the tunnel resolver IPv4 (127.0.0.1) into the IPv6 address
		expected := netip.AddrPortFrom(
			netip.MustParseAddr("fd00::7f00:1"),
			8053,
		).String()
		assert.Equal(t, expected, host)
	})

	t.Run("invalid IPv4 address", func(t *testing.T) {
		addr := netip.MustParseAddr("192.168.1.1")
		_, err := r.upstreamHostFromAddr(addr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expecting v6 address")
	})
}
