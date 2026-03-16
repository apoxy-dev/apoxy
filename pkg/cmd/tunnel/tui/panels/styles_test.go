package panels

import (
	"fmt"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/ansi"
	"github.com/stretchr/testify/assert"
)

func TestCellStyleWithANSI(t *testing.T) {
	ansiWrap := func(text string, color int) string {
		return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", color, text)
	}

	t.Run("full UUID fits in ConnIDWidth", func(t *testing.T) {
		uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890" // 36 chars
		styled := ansiWrap(uuid, 255)
		cell := CellStyle(ConnIDWidth).Render(styled)
		width := ansi.PrintableRuneWidth(cell)
		assert.Equal(t, ConnIDWidth, width, "full UUID cell should be exactly ConnIDWidth=%d wide", ConnIDWidth)
	})

	t.Run("connection row total width", func(t *testing.T) {
		cells := []string{
			CellStyle(ConnIDWidth).Render(ansiWrap("a1b2c3d4-e5f6-7890-abcd-ef1234567890", 255)),
			CellStyle(ConnStatusWidth).Render(ansiWrap("Healthy", 82)),
			CellStyle(ConnUptimeWidth).Render(ansiWrap("5m32s", 243)),
			CellStyle(ConnAddrsWidth).Render(ansiWrap("fd61:706f:7879::1", 243)),
		}
		row := LeftMargin + lipgloss.JoinHorizontal(lipgloss.Top, cells...)
		width := ansi.PrintableRuneWidth(row)
		expected := len(LeftMargin) + ConnIDWidth + ConnStatusWidth + ConnUptimeWidth + ConnAddrsWidth
		assert.Equal(t, expected, width, "connection row width")
	})

	t.Run("full IPv6+port fits in SrcWidth", func(t *testing.T) {
		// Typical ULA address with port
		addr := "fd61:706f:7879:1:0:5354:c0a8:101:8080" // 39 chars
		cell := CellStyle(SrcWidth).Render(addr)
		width := ansi.PrintableRuneWidth(cell)
		assert.Equal(t, SrcWidth, width, "IPv6+port cell width")
	})

	t.Run("traffic row total width", func(t *testing.T) {
		src := "fd61:706f:7879:1:0:5354:c0a8:101:8080"
		dst := "fd61:706f:7879:1:0:5354:c0a8:102:443"

		cells := []string{
			CellStyle(TimeWidth).Render(ansiWrap("15:04:05", 243)),
			CellStyle(ProtoWidth).Render(ansiWrap("TCP", 39)),
			CellStyle(SrcWidth).Render(src),
			lipgloss.NewStyle().Width(3).Render("→"),
			CellStyle(DstWidth).Render(dst),
			CellStyle(SizeWidth).Render(ansiWrap("1234", 243)),
			CellStyle(FlagsWidth).Render(ansiWrap("SYN", 243)),
			CellStyle(DirWidth).Render(ansiWrap("IN", 82)),
		}
		row := LeftMargin + lipgloss.JoinHorizontal(lipgloss.Top, cells...)
		width := ansi.PrintableRuneWidth(row)
		expected := len(LeftMargin) + TimeWidth + ProtoWidth + SrcWidth + 3 + DstWidth + SizeWidth + FlagsWidth + DirWidth
		assert.Equal(t, expected, width, "traffic row width")
		t.Logf("Traffic row total: %d cols", expected)
	})
}
