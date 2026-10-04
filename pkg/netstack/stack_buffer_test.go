package netstack_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

// TestStackTCPBufferMax checks that half of the largest TCP buffers holds the
// bytes in flight of one flow at 10 Gbps and 25 ms RTT.
func TestStackTCPBufferMax(t *testing.T) {
	ns, err := netstack.NewStack(1280, "", netstack.WithoutIPTables())
	require.NoError(t, err)
	t.Cleanup(ns.Close)

	const inFlight = 10e9 / 8 * 25e-3
	var rcv tcpip.TCPReceiveBufferSizeRangeOption
	require.Nil(t, ns.Stack.TransportProtocolOption(tcp.ProtocolNumber, &rcv))
	var snd tcpip.TCPSendBufferSizeRangeOption
	require.Nil(t, ns.Stack.TransportProtocolOption(tcp.ProtocolNumber, &snd))

	cases := []struct {
		name string
		max  int
	}{
		{name: "receive", max: rcv.Max},
		{name: "send", max: snd.Max},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.GreaterOrEqual(t, float64(tc.max/2), inFlight)
		})
	}
}
