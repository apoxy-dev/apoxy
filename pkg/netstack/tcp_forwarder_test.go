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

	// Splice packets between the two stacks
	go func() {
		if err := nettest.SplicePackets(ctx, serverStack, clientStack); err != nil && !errors.Is(err, context.Canceled) {
			panic(fmt.Errorf("packet splicing failed: %w", err))
		}
	}()

	// Setup the server stack to forward TCP packets to the hosts loopback interface.
	serverStack.SetTransportProtocolHandler(tcp.ProtocolNumber, netstack.TCPForwarder(ctx, serverStack.Stack, network.Loopback(), ""))

	// Generate a large blob of random blob to send to the client.
	blob := make([]byte, 1<<20)
	_, err = rand.Reader.Read(blob)
	require.NoError(t, err)

	// Calculate the checksum of the blob
	h := sha256.New()
	_, _ = h.Write(blob)
	expectedChecksum := hex.EncodeToString(h.Sum(nil))

	// Start a http server on the loopback interface, using httptest
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(blob)
	}))
	defer httpServer.Close()

	httpServerPort := httpServer.Listener.Addr().(*net.TCPAddr).Port

	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, nil)

	// Create a TCP connection from the client to the server via the forwarder and loopback interface.
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

	// Read the response body and calculate the checksum
	h = sha256.New()
	_, err = io.Copy(h, resp.Body)
	require.NoError(t, err)

	// Compare the checksums
	assert.Equal(t, expectedChecksum, hex.EncodeToString(h.Sum(nil)))
}
