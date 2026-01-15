package panels

import (
	"strings"
)

// HelpPanel displays the help information at the bottom.
type HelpPanel struct {
	width int
}

// NewHelpPanel creates a new help panel.
func NewHelpPanel() HelpPanel {
	return HelpPanel{}
}

// SetWidth sets the panel width.
func (p *HelpPanel) SetWidth(width int) {
	p.width = width
}

// View renders the help panel.
func (p HelpPanel) View() string {
	if p.width < 40 {
		return ""
	}

	var sb strings.Builder

	// Help line
	help := []string{
		HelpStyle.Render("j/k") + DimStyle.Render(":scroll"),
		HelpStyle.Render("g/G") + DimStyle.Render(":top/bottom"),
		HelpStyle.Render("t") + DimStyle.Render(":TCP"),
		HelpStyle.Render("u") + DimStyle.Render(":UDP"),
		HelpStyle.Render("i") + DimStyle.Render(":ICMP"),
		HelpStyle.Render("a") + DimStyle.Render(":all"),
		HelpStyle.Render("c") + DimStyle.Render(":clear"),
		HelpStyle.Render("q") + DimStyle.Render(":quit"),
	}

	helpLine := LeftMargin + strings.Join(help, "  ")
	sb.WriteString(helpLine)

	return sb.String()
}

// Height returns the height of the help panel.
func (p HelpPanel) Height() int {
	return 1
}
