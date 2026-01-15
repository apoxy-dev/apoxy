package panels

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

const maxPackets = 1000

// ProtocolFilter defines which protocols to show.
type ProtocolFilter int

const (
	FilterAll ProtocolFilter = iota
	FilterTCP
	FilterUDP
	FilterICMP
)

// TrafficPanel displays live packet traffic.
type TrafficPanel struct {
	width    int
	height   int
	packets  []connection.PacketInfo
	filter   ProtocolFilter
	scrollY  int
	autoTail bool // auto-scroll to bottom
}

// NewTrafficPanel creates a new traffic panel.
func NewTrafficPanel() TrafficPanel {
	return TrafficPanel{
		packets:  make([]connection.PacketInfo, 0, maxPackets),
		filter:   FilterAll,
		autoTail: true,
	}
}

// SetSize sets the panel dimensions.
func (p *TrafficPanel) SetSize(width, height int) {
	p.width = width
	p.height = height
}

// AddPacket adds a packet to the display.
func (p *TrafficPanel) AddPacket(info connection.PacketInfo) {
	p.packets = append(p.packets, info)
	if len(p.packets) > maxPackets {
		p.packets = p.packets[1:]
		if p.scrollY > 0 {
			p.scrollY--
		}
	}
	if p.autoTail {
		p.scrollToBottom()
	}
}

// Clear removes all packets.
func (p *TrafficPanel) Clear() {
	p.packets = p.packets[:0]
	p.scrollY = 0
}

// SetFilter sets the protocol filter.
func (p *TrafficPanel) SetFilter(f ProtocolFilter) {
	p.filter = f
	p.scrollY = 0
}

// ScrollUp scrolls up by one line.
func (p *TrafficPanel) ScrollUp() {
	p.autoTail = false
	if p.scrollY > 0 {
		p.scrollY--
	}
}

// ScrollDown scrolls down by one line.
func (p *TrafficPanel) ScrollDown() {
	filtered := p.filteredPackets()
	maxScroll := len(filtered) - p.visibleLines()
	if maxScroll < 0 {
		maxScroll = 0
	}
	if p.scrollY < maxScroll {
		p.scrollY++
	}
	if p.scrollY >= maxScroll {
		p.autoTail = true
	}
}

// ScrollToTop scrolls to the top.
func (p *TrafficPanel) ScrollToTop() {
	p.autoTail = false
	p.scrollY = 0
}

// ScrollToBottom scrolls to the bottom.
func (p *TrafficPanel) ScrollToBottom() {
	p.autoTail = true
	p.scrollToBottom()
}

func (p *TrafficPanel) scrollToBottom() {
	filtered := p.filteredPackets()
	maxScroll := len(filtered) - p.visibleLines()
	if maxScroll < 0 {
		maxScroll = 0
	}
	p.scrollY = maxScroll
}

func (p *TrafficPanel) visibleLines() int {
	return p.height - 3 // account for header + column names
}

func (p *TrafficPanel) filteredPackets() []connection.PacketInfo {
	if p.filter == FilterAll {
		return p.packets
	}

	var result []connection.PacketInfo
	for _, pkt := range p.packets {
		switch p.filter {
		case FilterTCP:
			if pkt.Protocol == connection.ProtocolTCP {
				result = append(result, pkt)
			}
		case FilterUDP:
			if pkt.Protocol == connection.ProtocolUDP {
				result = append(result, pkt)
			}
		case FilterICMP:
			if pkt.Protocol == connection.ProtocolICMP {
				result = append(result, pkt)
			}
		}
	}
	return result
}

// FilterName returns the name of the current filter.
func (p *TrafficPanel) FilterName() string {
	switch p.filter {
	case FilterTCP:
		return "TCP"
	case FilterUDP:
		return "UDP"
	case FilterICMP:
		return "ICMP"
	default:
		return "all"
	}
}

// View renders the traffic panel.
func (p TrafficPanel) View() string {
	if p.width < 40 || p.height < 4 {
		return ""
	}

	var sb strings.Builder

	// Header with filter info
	filterInfo := fmt.Sprintf(" TRAFFIC (%s) ", p.FilterName())
	headerContent := HeaderStyle.Render(filterInfo)

	header := headerContent
	headerBox := TrafficBorderStyle.Width(p.width - 2).Render(header)
	sb.WriteString(headerBox)
	sb.WriteString("\n")

	// Column headers using lipgloss for proper alignment
	headerCells := []string{
		CellStyle(TimeWidth).Render(ColumnHeaderStyle.Render("TIME")),
		CellStyle(ProtoWidth).Render(ColumnHeaderStyle.Render("PROTO")),
		CellStyle(SrcWidth).Render(ColumnHeaderStyle.Render("SOURCE")),
		lipgloss.NewStyle().Width(3).Render(""),
		CellStyle(DstWidth).Render(ColumnHeaderStyle.Render("DESTINATION")),
		CellStyle(SizeWidth).Render(ColumnHeaderStyle.Render("SIZE")),
		CellStyle(FlagsWidth).Render(ColumnHeaderStyle.Render("FLAGS")),
		CellStyle(DirWidth).Render(ColumnHeaderStyle.Render("DIR")),
	}
	columnHeader := LeftMargin + lipgloss.JoinHorizontal(lipgloss.Top, headerCells...)
	sb.WriteString(columnHeader)
	sb.WriteString("\n")

	// Packet lines
	filtered := p.filteredPackets()
	visibleLines := p.visibleLines()

	start := p.scrollY
	end := start + visibleLines
	if end > len(filtered) {
		end = len(filtered)
	}
	if start > end {
		start = end
	}

	for i := start; i < end; i++ {
		pkt := filtered[i]
		line := p.formatPacket(pkt)
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	// Fill remaining space with empty lines
	for i := end - start; i < visibleLines; i++ {
		sb.WriteString("\n")
	}

	return sb.String()
}

func (p *TrafficPanel) formatPacket(pkt connection.PacketInfo) string {
	timestamp := pkt.Timestamp.Format("15:04:05")

	protoStr := pkt.Protocol.String()
	var proto string
	switch pkt.Protocol {
	case connection.ProtocolTCP:
		proto = TCPStyle.Render(protoStr)
	case connection.ProtocolUDP:
		proto = UDPStyle.Render(protoStr)
	case connection.ProtocolICMP:
		proto = ICMPStyle.Render(protoStr)
	default:
		proto = UnknownProtoStyle.Render(protoStr)
	}

	var src, dst string
	if pkt.Protocol == connection.ProtocolICMP {
		src = pkt.SrcIP.String()
		dst = pkt.DstIP.String()
	} else {
		src = fmt.Sprintf("%s:%d", pkt.SrcIP.String(), pkt.SrcPort)
		dst = fmt.Sprintf("%s:%d", pkt.DstIP.String(), pkt.DstPort)
	}

	size := fmt.Sprintf("%d", pkt.Size)

	var dir string
	if pkt.Direction == connection.DirectionInbound {
		dir = InboundStyle.Render("IN")
	} else {
		dir = OutboundStyle.Render("OUT")
	}

	flags := ""
	if pkt.Protocol == connection.ProtocolTCP {
		flags = pkt.TCPFlags.String()
	}

	cells := []string{
		CellStyle(TimeWidth).Render(DimStyle.Render(timestamp)),
		CellStyle(ProtoWidth).Render(proto),
		CellStyle(SrcWidth).Render(src),
		lipgloss.NewStyle().Width(3).Render("→"),
		CellStyle(DstWidth).Render(dst),
		CellStyle(SizeWidth).Render(DimStyle.Render(size)),
		CellStyle(FlagsWidth).Render(DimStyle.Render(flags)),
		CellStyle(DirWidth).Render(dir),
	}
	return LeftMargin + lipgloss.JoinHorizontal(lipgloss.Top, cells...)
}
