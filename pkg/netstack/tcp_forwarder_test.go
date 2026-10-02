package netstack_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	"github.com/dpeckett/network"
	"github.com/dpeckett/network/nettest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

func TestTCPForwarder(t *testing.T) {
	var serverPcapPath, clientPcapPath string
	if testing.Verbose() {
		serverPcapPath = "server.pcap"
		clientPcapPath = "client.pcap"
	}

	serverStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.1"), serverPcapPath)
	require.NoError(t, err)
	t.Cleanup(serverStack.Close)

	clientStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.2"), clientPcapPath)
	require.NoError(t, err)
	t.Cleanup(clientStack.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Move packets between the two stacks.
	go func() {
		if err := nettest.SplicePackets(ctx, serverStack, clientStack); err != nil && !errors.Is(err, context.Canceled) {
			panic(fmt.Errorf("packet splicing failed: %w", err))
		}
	}()

	// The server stack forwards TCP connections to the host loopback.
	serverStack.SetTransportProtocolHandler(tcp.ProtocolNumber, netstack.TCPForwarder(ctx, serverStack.Stack, network.Loopback()))

	// Make 1 MiB of random data for the client.
	blob := make([]byte, 1<<20)
	_, err = rand.Reader.Read(blob)
	require.NoError(t, err)

	// Get the checksum of the data.
	h := sha256.New()
	_, _ = h.Write(blob)
	expectedChecksum := hex.EncodeToString(h.Sum(nil))

	// Start an HTTP server on the loopback interface.
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(blob)
	}))
	defer httpServer.Close()

	httpServerPort := httpServer.Listener.Addr().(*net.TCPAddr).Port

	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, nil)

	// Connect from the client through the forwarder to the server on loopback.
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: clientNetwork.DialContext,
		},
	}

	resp, err := httpClient.Get("http://10.0.0.1:" + strconv.Itoa(httpServerPort))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the response body and get its checksum.
	h = sha256.New()
	_, err = io.Copy(h, resp.Body)
	require.NoError(t, err)

	// Compare the checksums.
	assert.Equal(t, expectedChecksum, hex.EncodeToString(h.Sum(nil)))
}

func TestUnmap4in6(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{name: "IPv4", addr: "10.0.0.5", want: "10.0.0.5"},
		{name: "IPv4-mapped", addr: "::ffff:10.0.0.5", want: "10.0.0.5"},
		{name: "NAT64", addr: "64:ff9b::a00:5", want: "10.0.0.5"},
		{name: "v1 overlay with IPv4", addr: "fd61:706f:7879:12:3400:abcd:a00:5", want: "10.0.0.5"},
		{name: "v1 overlay with loopback", addr: "fd61:706f:7879:12:3400:abcd:7f00:1", want: "127.0.0.1"},
		{name: "v1 overlay /96 address", addr: "fd61:706f:7879:12:3400:abcd::", want: "0.0.0.0"},
		{name: "v2 attachment address", addr: "fd61:706f:7879:12:3456:7800::1", want: "fd61:706f:7879:12:3456:7800::1"},
		{name: "ULA outside the overlay", addr: "fd00:1::1", want: "fd00:1::1"},
		{name: "global IPv6", addr: "2001:db8::a00:5", want: "2001:db8::a00:5"},
		{name: "IPv6 loopback", addr: "::1", want: "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := netstack.Unmap4in6(netip.MustParseAddr(tc.addr))
			assert.Equal(t, netip.MustParseAddr(tc.want), got)
		})
	}
}
