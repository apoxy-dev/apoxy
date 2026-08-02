package agent

import "time"

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

// ConnectionStatus is a point-in-time view of one MinConns slot. Slot is
// stable for the process lifetime, while Relay may change when that slot
// reconnects. RXBytes and TXBytes are from the agent's perspective.
type ConnectionStatus struct {
	Slot        int
	Relay       string
	State       ConnectionState
	Latency     time.Duration
	ConnectedAt time.Time
	RXBytes     uint64
	TXBytes     uint64
	Err         error
}

// reportConnection publishes a status snapshot when the caller requested
// observation. The observer runs synchronously and must return promptly.
func (cfg Config) reportConnection(status ConnectionStatus) {
	if cfg.ConnectionObserver != nil && status.Slot >= 0 {
		cfg.ConnectionObserver(status)
	}
}
