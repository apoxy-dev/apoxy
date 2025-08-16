package kex_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/kex"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

func TestServer(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	issuer, err := token.NewIssuer(privateKeyPEM)
	require.NoError(t, err)

	validator, err := token.NewInMemoryValidator(publicKeyPEM)
	require.NoError(t, err)

	tokenStr, _, err := issuer.IssueToken("test-agent", time.Minute*5)
	require.NoError(t, err)

	handler, err := icx.NewHandler(icx.WithLocalAddr(mustNewFullAddress("127.0.0.1", 6081)),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()))
	require.NoError(t, err)

	serverImpl := kex.NewServer(t.Context(), handler, validator, 100*time.Millisecond)
	httpHandler := serverImpl.Routes()

	testHTTPServer := httptest.NewServer(httpHandler)
	defer testHTTPServer.Close()

	client := kex.NewClient(testHTTPServer.URL, tokenStr)

	t.Run("Requires Authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/network", nil)
		w := httptest.NewRecorder()
		httpHandler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Connect", func(t *testing.T) {
		connectResp, err := client.Connect("127.0.0.1:6081")
		require.NoError(t, err)

		assert.NotEmpty(t, connectResp.Keys.Send)
		assert.NotEmpty(t, connectResp.Keys.Recv)
		assert.Equal(t, 1, connectResp.Keys.Epoch)
		assert.Equal(t, 1, len(connectResp.Addresses))
	})

	t.Run("Disconnect", func(t *testing.T) {
		connectResp, err := client.Connect("127.0.0.1:6081")
		require.NoError(t, err)

		err = client.Disconnect(connectResp.NetworkID)
		require.NoError(t, err)
	})

	t.Run("RenewKeys", func(t *testing.T) {
		connectResp, err := client.Connect("127.0.0.1:6081")
		require.NoError(t, err)

		renewResp, err := client.RenewKeys(connectResp.NetworkID)
		require.NoError(t, err)

		assert.Equal(t, 2, renewResp.Keys.Epoch)
		assert.NotEmpty(t, renewResp.Keys.Send)
		assert.NotEmpty(t, renewResp.Keys.Recv)
	})

	t.Run("ExpiredNetworkCleanup", func(t *testing.T) {
		connectResp, err := client.Connect("127.0.0.1:6081")
		require.NoError(t, err)

		// Wait for the network to expire
		time.Sleep(time.Second)

		serverImpl.CleanupExpiredNetworks()

		// Attempt to disconnect after expiry
		err = client.Disconnect(connectResp.NetworkID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disconnect failed")
	})
}

func mustNewFullAddress(ip string, port uint16) *tcpip.FullAddress {
	netAddr := netip.MustParseAddr(ip)

	switch netAddr.BitLen() {
	case 32:
		addr := tcpip.AddrFrom4Slice(netAddr.AsSlice())
		return &tcpip.FullAddress{
			Addr: addr,
			Port: port,
		}
	case 128:
		addr := tcpip.AddrFrom16Slice(netAddr.AsSlice())
		return &tcpip.FullAddress{
			Addr: addr,
			Port: port,
		}
	default:
		panic("Unsupported IP address length")
	}
}
