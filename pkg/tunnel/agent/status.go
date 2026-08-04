package agent

import (
	"net/netip"
	"time"
)

// ConnectionState is the client-observed lifecycle state of one desired
// relay connection. It deliberately carries no primary or failover role:
// every live relay connection is equivalent at the API layer.
type ConnectionState string

const (
	ConnectionStateConnecting ConnectionState = "connecting"
	ConnectionStateConnected  ConnectionState = "connected"
	ConnectionStateDraining   ConnectionState = "draining"
	ConnectionStateEnded      ConnectionState = "ended"
)

// ConnectionStatus is a point-in-time view of one relay session. Under the
// MinConns policy, Slot identifies the connection slot. The slot is stable
// for the process lifetime. Relay can change when the slot reconnects.
// Under ConnectAll there are no slots and Slot is -1. RXBytes and TXBytes
// count from the agent's side. Prefixes is the set of transit prefixes with
// installed routes for this session. It fills in on the periodic snapshots
// after the initial route exchange completes.
type ConnectionStatus struct {
	Slot        int
	Relay       string
	State       ConnectionState
	Latency     time.Duration
	ConnectedAt time.Time
	RXBytes     uint64
	TXBytes     uint64
	Prefixes    []netip.Prefix
	Err         error
}

// reportConnection publishes a status snapshot when the caller requested
// observation. The observer runs synchronously and must return promptly.
func (cfg Config) reportConnection(status ConnectionStatus) {
	if cfg.ConnectionObserver != nil && status.Slot >= 0 {
		cfg.ConnectionObserver(status)
	}
	if cfg.SessionObserver != nil {
		cfg.SessionObserver(status)
	}
}
