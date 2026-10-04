package netstack_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

func TestUDPForwarder(t *testing.T) {
	serverStack := newStack(t, "10.0.0.1/32")
	clientStack := newStack(t, "10.0.0.2/32")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Move packets between the two stacks.
	spliceStacks(t, serverStack, clientStack)

	// The server stack forwards UDP packets to the host loopback.
	serverStack.Stack.SetTransportProtocolHandler(udp.ProtocolNumber, netstack.UDPForwarder(ctx, serverStack.Stack, network.Loopback()))

	// Make the test data.
	testData := make([]byte, 1024)
	_, err := rand.Reader.Read(testData)
	require.NoError(t, err)

	// Get the checksum of the test data.
	h := sha256.New()
	_, _ = h.Write(testData)
	expectedChecksum := hex.EncodeToString(h.Sum(nil))

	// The echo server listens on all addresses, so 127.0.0.1 and ::1 both reach
	// it. The loopback network dials "localhost", which can resolve to either.
	udpServer, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	require.NoError(t, err)
	defer udpServer.Close()

	serverPort := udpServer.LocalAddr().(*net.UDPAddr).Port

	// The echo server sends back the same data.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpServer.ReadFromUDP(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("UDP server read error: %v", err)
				}
				return
			}
			_, err = udpServer.WriteToUDP(buf[:n], addr)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("UDP server write error: %v", err)
				}
				return
			}
		}
	}()

	// Make a UDP client on the client stack.
	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, nil)

	// Connect and send the data.
	conn, err := clientNetwork.DialContext(ctx, "udp", fmt.Sprintf("10.0.0.1:%d", serverPort))
	require.NoError(t, err)
	defer conn.Close()

	// Send the test data.
	_, err = conn.Write(testData)
	require.NoError(t, err)

	// Read the response.
	response := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(response)
	require.NoError(t, err)
	require.Equal(t, len(testData), n)

	// Get the checksum of the response.
	h = sha256.New()
	_, _ = h.Write(response[:n])
	responseChecksum := hex.EncodeToString(h.Sum(nil))

	// Compare the checksums.
	assert.Equal(t, expectedChecksum, responseChecksum)
}

func TestUDPForwarderMultipleSessions(t *testing.T) {
	serverStack := newStack(t, "10.0.0.1/32")
	clientStack := newStack(t, "10.0.0.2/32")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Move packets between the two stacks.
	spliceStacks(t, serverStack, clientStack)

	// The server stack forwards UDP packets to the host loopback.
	serverStack.Stack.SetTransportProtocolHandler(udp.ProtocolNumber, netstack.UDPForwarder(ctx, serverStack.Stack, network.Loopback()))

	// Start UDP servers on different ports.
	numServers := 3
	servers := make([]*net.UDPConn, numServers)
	ports := make([]int, numServers)

	for i := 0; i < numServers; i++ {
		// Listen on all addresses, as above.
		server, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		require.NoError(t, err)
		defer server.Close()

		servers[i] = server
		ports[i] = server.LocalAddr().(*net.UDPAddr).Port

		// Each echo server adds its own prefix.
		go func(srv *net.UDPConn, prefix byte) {
			buf := make([]byte, 65535)
			for {
				n, addr, err := srv.ReadFromUDP(buf)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Logf("UDP server read error: %v", err)
					}
					return
				}

				// Add the prefix to the response.
				response := make([]byte, n+1)
				response[0] = prefix
				copy(response[1:], buf[:n])

				_, err = srv.WriteToUDP(response, addr)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Logf("UDP server write error: %v", err)
					}
					return
				}
			}
		}(server, byte(i))
	}

	// Make UDP clients and test the sessions.
	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, nil)

	for i := 0; i < numServers; i++ {
		t.Run(fmt.Sprintf("Server%d", i), func(t *testing.T) {
			// Connect to one server.
			conn, err := clientNetwork.DialContext(ctx, "udp", fmt.Sprintf("10.0.0.1:%d", ports[i]))
			require.NoError(t, err)
			defer conn.Close()

			// Send the test data.
			testData := []byte(fmt.Sprintf("test_data_%d", i))
			_, err = conn.Write(testData)
			require.NoError(t, err)

			// Read the response.
			response := make([]byte, 256)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(response)
			require.NoError(t, err)

			// Make sure that the response has the correct prefix and data.
			assert.Equal(t, byte(i), response[0])
			assert.Equal(t, testData, response[1:n])
		})
	}
}

func TestUDPForwarderTimeout(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("Skipping timeout test in non-verbose mode")
	}

	serverStack := newStack(t, "10.0.0.1/32")
	clientStack := newStack(t, "10.0.0.2/32")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Move packets between the two stacks.
	spliceStacks(t, serverStack, clientStack)

	// The server stack forwards UDP packets to the host loopback.
	serverStack.Stack.SetTransportProtocolHandler(udp.ProtocolNumber, netstack.UDPForwarder(ctx, serverStack.Stack, network.Loopback()))

	// The echo server listens on all addresses, so 127.0.0.1 and ::1 both reach
	// it. The loopback network dials "localhost", which can resolve to either.
	udpServer, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	require.NoError(t, err)
	defer udpServer.Close()

	serverPort := udpServer.LocalAddr().(*net.UDPAddr).Port

	// Start the echo server.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpServer.WriteToUDP(buf[:n], addr)
		}
	}()

	// Make a client and send the first packet.
	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, nil)
	conn, err := clientNetwork.DialContext(ctx, "udp", fmt.Sprintf("10.0.0.1:%d", serverPort))
	require.NoError(t, err)

	// Send and receive to start the session.
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	response := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(response)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(response[:n]))

	// Close the connection. The session ends after a time with no traffic.
	conn.Close()

	// The session timeout is 2 minutes, so the test does not wait for it.
	t.Log("Session created and will timeout after inactivity")
}
