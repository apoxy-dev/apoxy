package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// Run starts the TUI with the given packet channel and status provider.
// It blocks until the TUI is closed (user presses 'q' or Ctrl+C).
func Run(ctx context.Context, packetsCh <-chan connection.PacketInfo, statusProvider StatusProvider) error {
	model := NewModel(packetsCh, statusProvider)

	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("running TUI: %w", err)
	}

	return nil
}
