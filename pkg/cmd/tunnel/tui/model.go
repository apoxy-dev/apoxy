package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/apoxy-dev/apoxy/pkg/cmd/tunnel/tui/panels"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// Model is the main Bubble Tea model for the TUI.
type Model struct {
	width  int
	height int

	header  panels.HeaderPanel
	traffic panels.TrafficPanel
	help    panels.HelpPanel

	keys     keyMap
	quitting bool

	packetsCh      <-chan connection.PacketInfo
	statusProvider StatusProvider
}

// NewModel creates a new TUI model.
func NewModel(packetsCh <-chan connection.PacketInfo, statusProvider StatusProvider) Model {
	return Model{
		header:         panels.NewHeaderPanel(),
		traffic:        panels.NewTrafficPanel(),
		help:           panels.NewHelpPanel(),
		keys:           DefaultKeyMap,
		packetsCh:      packetsCh,
		statusProvider: statusProvider,
	}
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		waitForPacket(m.packetsCh),
		tickStatus(),
	)
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.header.SetWidth(msg.Width)
		m.help.SetWidth(msg.Width)
		headerHeight := m.header.Height()
		helpHeight := m.help.Height()
		m.traffic.SetSize(msg.Width, msg.Height-headerHeight-helpHeight-1)
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Quit

		case key.Matches(msg, m.keys.ScrollUp):
			m.traffic.ScrollUp()
			return m, nil

		case key.Matches(msg, m.keys.ScrollDown):
			m.traffic.ScrollDown()
			return m, nil

		case key.Matches(msg, m.keys.Top):
			m.traffic.ScrollToTop()
			return m, nil

		case key.Matches(msg, m.keys.Bottom):
			m.traffic.ScrollToBottom()
			return m, nil

		case key.Matches(msg, m.keys.FilterTCP):
			m.traffic.SetFilter(panels.FilterTCP)
			return m, nil

		case key.Matches(msg, m.keys.FilterUDP):
			m.traffic.SetFilter(panels.FilterUDP)
			return m, nil

		case key.Matches(msg, m.keys.FilterICMP):
			m.traffic.SetFilter(panels.FilterICMP)
			return m, nil

		case key.Matches(msg, m.keys.FilterAll):
			m.traffic.SetFilter(panels.FilterAll)
			return m, nil

		case key.Matches(msg, m.keys.Clear):
			m.traffic.Clear()
			return m, nil
		}

	case PacketMsg:
		m.traffic.AddPacket(msg.Info)
		return m, waitForPacket(m.packetsCh)

	case TickMsg:
		if m.statusProvider != nil {
			m.header.SetTunnelInfo(m.statusProvider.GetTunnelInfo())
			m.header.SetConnections(m.statusProvider.GetConnections())
		}
		return m, tickStatus()
	}

	return m, nil
}

// View renders the model.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	return m.header.View() + "\n" + m.traffic.View() + m.help.View()
}

// waitForPacket waits for a packet from the channel.
func waitForPacket(ch <-chan connection.PacketInfo) tea.Cmd {
	return func() tea.Msg {
		pkt, ok := <-ch
		if !ok {
			return nil
		}
		return PacketMsg{Info: pkt}
	}
}

// tickStatus sends periodic status updates.
func tickStatus() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}
