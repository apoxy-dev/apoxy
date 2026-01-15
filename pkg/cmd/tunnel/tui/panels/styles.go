package panels

import (
	"time"

	"github.com/charmbracelet/lipgloss"
)

const (
	// LeftMargin is the left margin for content inside panels
	LeftMargin = "  "

	// CONNECTIONS table column widths
	ConnIDWidth     = 10
	ConnStatusWidth = 12
	ConnUptimeWidth = 10
	ConnAddrsWidth  = 40

	// TRAFFIC table column widths
	TimeWidth  = 10
	ProtoWidth = 6
	SrcWidth   = 28
	DstWidth   = 28
	SizeWidth  = 7
	FlagsWidth = 6
	DirWidth   = 4
)

// CellStyle returns a fixed-width cell style for proper column alignment.
// This handles ANSI escape codes correctly by using visual width.
func CellStyle(width int) lipgloss.Style {
	return lipgloss.NewStyle().Width(width).MaxWidth(width).Inline(true)
}

var (
	// Panel styles
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("87")) // cyan

	BorderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			MarginTop(1)

	TrafficBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder(), true, true, false, true). // top and sides only
				BorderForeground(lipgloss.Color("240"))

	// Text styles
	LabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250"))

	ValueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("255"))

	DimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243"))

	// Status styles
	HealthyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")) // green

	UnhealthyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")) // red

	// Protocol styles
	TCPStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")) // blue

	UDPStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("208")) // orange

	ICMPStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("141")) // purple

	UnknownProtoStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("243")) // gray

	// Direction styles
	InboundStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")) // green

	OutboundStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("226")) // yellow

	// Help style
	HelpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243"))

	// Column header style
	ColumnHeaderStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("250")).
				Bold(true)
)

// TunnelInfo contains information about the tunnel.
type TunnelInfo struct {
	Name       string
	UID        string
	ServerAddr string
	HasToken   bool
	Mode       string
	DNSAddr    string
	HealthAddr string
}

// ConnectionStatus contains status information about a single connection.
type ConnectionStatus struct {
	ID          string
	IsHealthy   bool
	ConnectedAt time.Time
	LocalAddrs  []string
}
