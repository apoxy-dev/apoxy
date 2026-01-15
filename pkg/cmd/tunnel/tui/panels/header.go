package panels

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// HeaderPanel displays tunnel info and connection status.
type HeaderPanel struct {
	width       int
	tunnelInfo  TunnelInfo
	connections []ConnectionStatus
}

// NewHeaderPanel creates a new header panel.
func NewHeaderPanel() HeaderPanel {
	return HeaderPanel{}
}

// SetWidth sets the panel width.
func (p *HeaderPanel) SetWidth(width int) {
	p.width = width
}

// SetTunnelInfo updates the tunnel info.
func (p *HeaderPanel) SetTunnelInfo(info TunnelInfo) {
	p.tunnelInfo = info
}

// SetConnections updates the connection status list.
func (p *HeaderPanel) SetConnections(conns []ConnectionStatus) {
	p.connections = conns
}

// View renders the header panel.
func (p HeaderPanel) View() string {
	if p.width < 40 {
		return ""
	}

	var sb strings.Builder

	// Tunnel info section
	tunnelHeader := HeaderStyle.Render(" TUNNEL ")
	tokenDisplay := "******"
	if !p.tunnelInfo.HasToken {
		tokenDisplay = "<none>"
	}

	info1 := fmt.Sprintf("%s%s: %-20s  %s: %-30s  %s: %s",
		LeftMargin,
		LabelStyle.Render("Name"), ValueStyle.Render(p.tunnelInfo.Name),
		LabelStyle.Render("Server"), ValueStyle.Render(p.tunnelInfo.ServerAddr),
		LabelStyle.Render("Mode"), ValueStyle.Render(p.tunnelInfo.Mode))

	info2 := fmt.Sprintf("%s%s: %-20s  %s: %s",
		LeftMargin,
		LabelStyle.Render("Token"), ValueStyle.Render(tokenDisplay),
		LabelStyle.Render("DNS"), ValueStyle.Render(p.tunnelInfo.DNSAddr))

	tunnelBox := BorderStyle.Width(p.width - 2).Render(
		tunnelHeader + "\n" + info1 + "\n" + info2)
	sb.WriteString(tunnelBox)
	sb.WriteString("\n")

	// Connections section
	activeCount := 0
	for _, c := range p.connections {
		if c.IsHealthy {
			activeCount++
		}
	}

	connHeader := HeaderStyle.Render(fmt.Sprintf(" CONNECTIONS (%d active) ", activeCount))

	// Column headers using lipgloss for proper alignment
	headerCells := []string{
		CellStyle(ConnIDWidth).Render(ColumnHeaderStyle.Render("ID")),
		CellStyle(ConnStatusWidth).Render(ColumnHeaderStyle.Render("STATUS")),
		CellStyle(ConnUptimeWidth).Render(ColumnHeaderStyle.Render("UPTIME")),
		CellStyle(ConnAddrsWidth).Render(ColumnHeaderStyle.Render("ADDRESSES")),
	}
	columnHeaders := LeftMargin + lipgloss.JoinHorizontal(lipgloss.Top, headerCells...)

	var connLines []string
	connLines = append(connLines, columnHeaders)

	if len(p.connections) == 0 {
		connLines = append(connLines, LeftMargin+DimStyle.Render("No connections"))
	} else {
		for _, conn := range p.connections {
			status := HealthyStyle.Render("Healthy")
			if !conn.IsHealthy {
				status = UnhealthyStyle.Render("Unhealthy")
			}

			duration := formatDuration(time.Since(conn.ConnectedAt))
			addrs := strings.Join(conn.LocalAddrs, ", ")
			if len(addrs) > 40 {
				addrs = addrs[:37] + "..."
			}

			cells := []string{
				CellStyle(ConnIDWidth).Render(ValueStyle.Render(conn.ID)),
				CellStyle(ConnStatusWidth).Render(status),
				CellStyle(ConnUptimeWidth).Render(DimStyle.Render(duration)),
				CellStyle(ConnAddrsWidth).Render(DimStyle.Render(addrs)),
			}
			line := LeftMargin + lipgloss.JoinHorizontal(lipgloss.Top, cells...)
			connLines = append(connLines, line)
		}
	}

	connBox := BorderStyle.Width(p.width - 2).MarginTop(0).Render(
		connHeader + "\n" + strings.Join(connLines, "\n"))
	sb.WriteString(connBox)

	return sb.String()
}

// Height returns the height of the header panel.
func (p HeaderPanel) Height() int {
	// tunnel box: 1 margin + 1 top border + 3 content lines + 1 bottom border = 6
	// conn box: 1 top border + 1 header + 1 column header + connections + 1 bottom border
	tunnelHeight := 6
	connHeight := 4 + len(p.connections)
	if len(p.connections) == 0 {
		connHeight = 5
	}
	return tunnelHeight + connHeight
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
