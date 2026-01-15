package tui

import (
	"time"

	"github.com/apoxy-dev/apoxy/pkg/cmd/tunnel/tui/panels"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// Re-export types from panels for convenience
type TunnelInfo = panels.TunnelInfo
type ConnectionStatus = panels.ConnectionStatus

// TunnelInfoMsg is sent when tunnel info is updated.
type TunnelInfoMsg struct {
	Info TunnelInfo
}

// ConnectionStatusMsg is sent when connection status is updated.
type ConnectionStatusMsg struct {
	Connections []ConnectionStatus
}

// PacketMsg is sent when a new packet is observed.
type PacketMsg struct {
	Info connection.PacketInfo
}

// TickMsg is sent periodically to update status.
type TickMsg time.Time

// StatusProvider provides tunnel and connection status.
type StatusProvider interface {
	GetTunnelInfo() TunnelInfo
	GetConnections() []ConnectionStatus
}
