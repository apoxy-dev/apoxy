package alpha

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	liptable "github.com/charmbracelet/lipgloss/table"

	tunnelagent "github.com/apoxy-dev/apoxy/pkg/tunnel/agent"
)

var (
	statusOKStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	statusWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	statusErrorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	statusDimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	statusHeadingStyle = lipgloss.NewStyle().Bold(true)
	statusLabelStyle   = lipgloss.NewStyle().Width(8)
)

// tunnelRunStatus renders the immutable tunnel choices once and keeps one
// inline row per desired connection slot current underneath them. In a
// non-interactive session it emits transition-only lines instead.
type tunnelRunStatus struct {
	out       io.Writer
	plain     bool
	prog      *tea.Program
	done      chan struct{}
	runErr    error
	name      string
	vpc       string
	generated bool
	desired   int

	mu    sync.Mutex
	last  map[int]tunnelagent.ConnectionStatus
	outMu sync.Mutex
}

func newTunnelRunStatus(out io.Writer, name, vpc string, generated bool, desired int, interactive bool) *tunnelRunStatus {
	s := &tunnelRunStatus{
		out:       out,
		plain:     !interactive,
		name:      name,
		vpc:       vpc,
		generated: generated,
		desired:   desired,
		last:      make(map[int]tunnelagent.ConnectionStatus, desired),
	}
	if s.plain {
		fmt.Fprintln(out, tunnelSummaryLine("tunnel", name, generated))
		fmt.Fprintln(out, tunnelSummaryLine("vpc", vpc, false))
		fmt.Fprintln(out, "→ resolving nearest edges")
		for i := 0; i < desired; i++ {
			s.last[i] = tunnelagent.ConnectionStatus{Slot: i, State: tunnelagent.ConnectionStateConnecting}
		}
		return s
	}

	s.done = make(chan struct{})
	s.prog = tea.NewProgram(
		newTunnelStatusModel(name, vpc, generated, desired),
		tea.WithOutput(out),
		tea.WithInput(nil),
		tea.WithoutSignalHandler(),
	)
	go func() {
		_, s.runErr = s.prog.Run()
		close(s.done)
	}()
	return s
}

func tunnelSummaryLine(label, value string, generated bool) string {
	detail := value
	if generated {
		detail += " (generated)"
	}
	return fmt.Sprintf("✓ %-8s%s", label, detail)
}

func (s *tunnelRunStatus) alive() bool {
	if s.plain {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// Observe implements agent.Config.ConnectionObserver.
func (s *tunnelRunStatus) Observe(status tunnelagent.ConnectionStatus) {
	s.mu.Lock()
	previous, seen := s.last[status.Slot]
	s.last[status.Slot] = status
	s.mu.Unlock()

	if !s.plain && s.alive() {
		s.prog.Send(tunnelConnectionStatusMsg(status))
		return
	}
	if !s.plain || (seen && previous.State == status.State && previous.Relay == status.Relay) {
		return
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	fmt.Fprintln(s.out, plainConnectionLine(status))
}

func plainConnectionLine(status tunnelagent.ConnectionStatus) string {
	edge := relayDisplayName(status.Relay)
	latency := formatLatency(status.Latency)
	switch status.State {
	case tunnelagent.ConnectionStateConnected:
		return fmt.Sprintf("✓ connected  %s · %s", edge, latency)
	case tunnelagent.ConnectionStateDraining:
		return fmt.Sprintf("! draining   %s", edge)
	case tunnelagent.ConnectionStateEnded:
		return fmt.Sprintf("! ended      %s · reconnecting", edge)
	default:
		if status.Relay == "" {
			return "→ resolving nearest edges"
		}
		return fmt.Sprintf("→ connecting %s", edge)
	}
}

// Close leaves the final inline state in the terminal. If Bubble Tea failed,
// it replays the latest state as plain text so the command still has a record.
func (s *tunnelRunStatus) Close() {
	if s.plain {
		return
	}
	if s.alive() {
		s.prog.Send(tunnelStatusQuitMsg{})
	}
	<-s.done
	if s.runErr == nil {
		return
	}
	fmt.Fprintln(s.out, tunnelSummaryLine("tunnel", s.name, s.generated))
	fmt.Fprintln(s.out, tunnelSummaryLine("vpc", s.vpc, false))
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < s.desired; i++ {
		if status, ok := s.last[i]; ok {
			fmt.Fprintln(s.out, plainConnectionLine(status))
		}
	}
}

type (
	tunnelConnectionStatusMsg tunnelagent.ConnectionStatus
	tunnelStatusQuitMsg       struct{}
)

type tunnelStatusModel struct {
	spinner   spinner.Model
	name      string
	vpc       string
	generated bool
	rows      []tunnelagent.ConnectionStatus
	width     int
}

func newTunnelStatusModel(name, vpc string, generated bool, desired int) tunnelStatusModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	rows := make([]tunnelagent.ConnectionStatus, desired)
	for i := range rows {
		rows[i] = tunnelagent.ConnectionStatus{Slot: i, State: tunnelagent.ConnectionStateConnecting}
	}
	m := tunnelStatusModel{
		spinner:   sp,
		name:      name,
		vpc:       vpc,
		generated: generated,
		rows:      rows,
	}
	return m
}

func (m tunnelStatusModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m tunnelStatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case spinner.TickMsg:
		if !m.hasConnecting() {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tunnelConnectionStatusMsg:
		status := tunnelagent.ConnectionStatus(msg)
		wasConnecting := m.hasConnecting()
		if status.Slot >= 0 && status.Slot < len(m.rows) {
			m.rows[status.Slot] = status
		}
		if !wasConnecting && m.hasConnecting() {
			return m, m.spinner.Tick
		}
		return m, nil
	case tunnelStatusQuitMsg:
		return m, tea.Quit
	}
	return m, nil
}

func (m tunnelStatusModel) hasConnecting() bool {
	for _, row := range m.rows {
		if row.State == tunnelagent.ConnectionStateConnecting {
			return true
		}
	}
	return false
}

func (m tunnelStatusModel) View() string {
	name := m.name
	if m.generated {
		name += " " + statusDimStyle.Render("(generated)")
	}
	summary := lipgloss.JoinVertical(
		lipgloss.Left,
		statusSummaryRow("tunnel", name),
		statusSummaryRow("vpc", m.vpc),
	)

	connected := 0
	for _, row := range m.rows {
		if row.State == tunnelagent.ConnectionStateConnected || row.State == tunnelagent.ConnectionStateDraining {
			connected++
		}
	}
	heading := fmt.Sprintf("Connections %d/%d", connected, len(m.rows))
	body := lipgloss.JoinVertical(
		lipgloss.Left,
		m.resolutionLine(),
		statusHeadingStyle.Render(heading),
		m.connectionTable(),
	)
	return lipgloss.JoinVertical(lipgloss.Left, summary, "", body) + "\n"
}

func (m tunnelStatusModel) resolutionLine() string {
	for _, row := range m.rows {
		if row.Relay != "" {
			return lipgloss.JoinHorizontal(
				lipgloss.Top,
				statusOKStyle.Render("✓"),
				" resolved nearest edges",
			)
		}
	}
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		statusWarnStyle.Render("→"),
		" resolving nearest edges",
	)
}

func statusSummaryRow(label, value string) string {
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		statusOKStyle.Render("✓"),
		" ",
		statusLabelStyle.Render(label),
		value,
	)
}

func tunnelStatusHeaders(width int) []string {
	headers := []string{
		"",
		"EDGE",
		"STATUS",
		"LATENCY",
	}
	if width >= 58 {
		headers = append(headers, "UP")
	}
	if width >= 86 {
		headers = append(headers, "TX", "RX")
	}
	return headers
}

var tunnelStatusColumnWidths = [...]int{2, 13, 13, 8, 10, 11, 10}

func (m tunnelStatusModel) connectionTable() string {
	headers := tunnelStatusHeaders(m.width)
	widths := tunnelStatusColumnWidths[:len(headers)]
	rows := make([][]string, 0, len(m.rows))
	for _, status := range m.rows {
		rows = append(rows, m.connectionRow(status, len(headers)))
	}
	t := liptable.New().
		Headers(headers...).
		Rows(rows...).
		BorderTop(false).
		BorderBottom(false).
		BorderLeft(false).
		BorderRight(false).
		BorderHeader(false).
		BorderColumn(false).
		BorderRow(false).
		Wrap(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			style := lipgloss.NewStyle().Width(widths[col]).PaddingRight(1)
			if col == len(widths)-1 {
				style = style.PaddingRight(0)
			}
			if row == liptable.HeaderRow {
				return style.Inherit(statusDimStyle).Bold(true)
			}
			if row < 0 || row >= len(m.rows) {
				return style
			}
			switch col {
			case 0, 2:
				return style.Inherit(connectionStateStyle(m.rows[row].State))
			case 3, 4, 5, 6:
				return style.Inherit(statusDimStyle)
			default:
				return style
			}
		})
	return t.String()
}

func connectionStateStyle(state tunnelagent.ConnectionState) lipgloss.Style {
	switch state {
	case tunnelagent.ConnectionStateConnected:
		return statusOKStyle
	case tunnelagent.ConnectionStateDraining:
		return statusWarnStyle
	case tunnelagent.ConnectionStateEnded:
		return statusErrorStyle
	default:
		return statusWarnStyle
	}
}

func (m tunnelStatusModel) connectionRow(status tunnelagent.ConnectionStatus, columns int) []string {
	var icon, state string
	switch status.State {
	case tunnelagent.ConnectionStateConnected:
		icon, state = "✓", "connected"
	case tunnelagent.ConnectionStateDraining:
		icon, state = "!", "draining"
	case tunnelagent.ConnectionStateEnded:
		icon, state = "✗", "reconnecting"
	default:
		icon, state = m.spinner.View(), "connecting"
	}
	tx, rx := "—", "—"
	if !status.ConnectedAt.IsZero() {
		tx, rx = formatBytes(status.TXBytes), formatBytes(status.RXBytes)
	}
	values := []string{
		icon,
		relayDisplayName(status.Relay),
		state,
		formatLatency(status.Latency),
		formatUptime(status.ConnectedAt),
		tx,
		rx,
	}
	return values[:columns]
}

func relayDisplayName(addr string) string {
	if addr == "" {
		return "—"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	labels := strings.Split(host, ".")
	if len(labels) > 2 && labels[1] == "relay" {
		return labels[0]
	}
	return host
}

func formatLatency(latency time.Duration) string {
	if latency <= 0 {
		return "—"
	}
	if latency < time.Millisecond {
		return "<1 ms"
	}
	return fmt.Sprintf("%d ms", latency.Round(time.Millisecond)/time.Millisecond)
}

func formatUptime(connectedAt time.Time) string {
	if connectedAt.IsZero() {
		return "—"
	}
	d := time.Since(connectedAt).Truncate(time.Second)
	if d < 0 {
		d = 0
	}
	hours := int(d / time.Hour)
	minutes := int(d/time.Minute) % 60
	seconds := int(d/time.Second) % 60
	if hours > 0 {
		return fmt.Sprintf("%d:%02d:%02d", hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit && exp < 3; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGT"[exp])
}
