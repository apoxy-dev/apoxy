package netstack

import "gvisor.dev/gvisor/pkg/tcpip/transport/tcp/bbr"

func init() { bbr.Register() }

// TCPCongestionControl is the TCP congestion control of new stacks.
var TCPCongestionControl = "bbr"
