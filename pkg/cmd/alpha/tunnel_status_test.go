package alpha

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"

	tunnelagent "github.com/apoxy-dev/apoxy/pkg/tunnel/agent"
)

func TestTunnelStatusModelRendersOneRowPerConnection(t *testing.T) {
	m := newTunnelStatusModel("swift-hopper", "default", true, 2)
	require.Contains(t, m.View(), "→ resolving nearest edges")
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = updated.(tunnelStatusModel)
	now := time.Now().Add(-90 * time.Second)
	updates := []tunnelagent.ConnectionStatus{
		{
			Slot:        0,
			Relay:       "us-west-2.relay.apoxy.net:6081",
			State:       tunnelagent.ConnectionStateConnected,
			Latency:     3 * time.Millisecond,
			ConnectedAt: now,
			TXBytes:     12 * 1024,
			RXBytes:     84 * 1024,
		},
		{
			Slot:        1,
			Relay:       "us-east-1.relay.apoxy.net:6081",
			State:       tunnelagent.ConnectionStateConnected,
			Latency:     9 * time.Millisecond,
			ConnectedAt: now,
		},
	}
	for _, status := range updates {
		updated, _ := m.Update(tunnelConnectionStatusMsg(status))
		m = updated.(tunnelStatusModel)
	}

	view := m.View()
	require.Contains(t, view, "swift-hopper")
	require.Contains(t, view, "(generated)")
	require.Contains(t, view, "✓ tunnel  swift-hopper")
	require.Contains(t, view, "✓ vpc     default")
	require.Contains(t, view, "✓ resolved nearest edges")
	require.Contains(t, view, "Connections 2/2")
	require.Len(t, m.rows, 2)
	require.Equal(t, 2, strings.Count(view, "connected"))
	require.Contains(t, view, "us-west-2")
	require.Contains(t, view, "us-east-1")
	require.Contains(t, view, "3 ms")
	require.Contains(t, view, "9 ms")
	require.NotContains(t, view, "primary")
	require.NotContains(t, view, "failover")
}

func TestTunnelStatusColumnsStayFixedAcrossUpdates(t *testing.T) {
	m := newTunnelStatusModel("swift-hopper", "default", true, 1)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = updated.(tunnelStatusModel)
	wantWidth := lipgloss.Width(m.connectionTable())

	states := []tunnelagent.ConnectionState{
		tunnelagent.ConnectionStateConnecting,
		tunnelagent.ConnectionStateConnected,
		tunnelagent.ConnectionStateDraining,
		tunnelagent.ConnectionStateEnded,
	}
	for _, state := range states {
		updated, _ = m.Update(tunnelConnectionStatusMsg(tunnelagent.ConnectionStatus{
			Slot:        0,
			Relay:       "us-west-2.relay.apoxy.net:6081",
			State:       state,
			Latency:     27 * time.Millisecond,
			ConnectedAt: time.Now().Add(-7 * time.Second),
			TXBytes:     999 * 1024 * 1024,
			RXBytes:     12 * 1024,
		}))
		m = updated.(tunnelStatusModel)
		require.Equal(t, wantWidth, lipgloss.Width(m.connectionTable()), "columns moved for state %s", state)
	}
}

func TestTunnelRunStatusPlainOutputEmitsTransitionsOnly(t *testing.T) {
	var out bytes.Buffer
	status := newTunnelRunStatus(&out, "swift-hopper", "default", true, 1, false)
	connected := tunnelagent.ConnectionStatus{
		Slot:    0,
		Relay:   "us-west-2.relay.apoxy.net:6081",
		State:   tunnelagent.ConnectionStateConnected,
		Latency: 3 * time.Millisecond,
	}
	status.Observe(connected)
	connected.RXBytes = 1024
	status.Observe(connected)

	text := out.String()
	require.Contains(t, text, "✓ tunnel  swift-hopper (generated)")
	require.Contains(t, text, "vpc     default")
	require.Equal(t, 1, strings.Count(text, "resolving nearest edges"))
	require.Equal(t, 1, strings.Count(text, "connected"))
}

func TestTunnelStatusModelFitsTerminalWithoutClippingCells(t *testing.T) {
	for _, width := range []int{48, 64, 100} {
		t.Run(fmt.Sprintf("width_%d", width), func(t *testing.T) {
			m := newTunnelStatusModel("swift-hopper", "default", true, 1)
			updated, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: 30})
			m = updated.(tunnelStatusModel)
			updated, _ = m.Update(tunnelConnectionStatusMsg(tunnelagent.ConnectionStatus{
				Slot:        0,
				Relay:       "us-west-2.relay.apoxy.net:6081",
				State:       tunnelagent.ConnectionStateConnected,
				Latency:     27 * time.Millisecond,
				ConnectedAt: time.Now().Add(-7 * time.Second),
			}))
			m = updated.(tunnelStatusModel)

			view := m.View()
			require.Contains(t, view, "us-west-2")
			require.Contains(t, view, "connected")
			if width == 100 {
				require.Less(t, lipgloss.Width(m.connectionTable()), 70, "table should use its natural content width")
			}
			for _, line := range strings.Split(strings.TrimSuffix(view, "\n"), "\n") {
				require.Less(t, lipgloss.Width(line), width, "line must not reach the terminal autowrap column: %q", line)
			}
		})
	}
}

func TestRelayDisplayName(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{name: "production relay hostname", addr: "us-west-2.relay.apoxy.net:6081", want: "us-west-2"},
		{name: "staging relay hostname", addr: "eu-central-1.relay.staging.apoxy.net:6081", want: "eu-central-1"},
		{name: "IP address", addr: "127.0.0.1:6081", want: "127.0.0.1"},
		{name: "IPv6 address", addr: "[::1]:6081", want: "::1"},
		{name: "waiting", addr: "", want: "—"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, relayDisplayName(tc.addr))
		})
	}
}
