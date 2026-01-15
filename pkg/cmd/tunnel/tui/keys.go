package tui

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Quit       key.Binding
	ScrollUp   key.Binding
	ScrollDown key.Binding
	Top        key.Binding
	Bottom     key.Binding
	FilterTCP  key.Binding
	FilterUDP  key.Binding
	FilterICMP key.Binding
	FilterAll  key.Binding
	Clear      key.Binding
}

var DefaultKeyMap = keyMap{
	Quit:       key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	ScrollUp:   key.NewBinding(key.WithKeys("k", "up"), key.WithHelp("k/↑", "up")),
	ScrollDown: key.NewBinding(key.WithKeys("j", "down"), key.WithHelp("j/↓", "down")),
	Top:        key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
	Bottom:     key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
	FilterTCP:  key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "TCP")),
	FilterUDP:  key.NewBinding(key.WithKeys("u"), key.WithHelp("u", "UDP")),
	FilterICMP: key.NewBinding(key.WithKeys("i"), key.WithHelp("i", "ICMP")),
	FilterAll:  key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "all")),
	Clear:      key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "clear")),
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.FilterTCP, k.FilterUDP, k.FilterICMP, k.FilterAll, k.Clear, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.ScrollUp, k.ScrollDown, k.Top, k.Bottom},
		{k.FilterTCP, k.FilterUDP, k.FilterICMP, k.FilterAll},
		{k.Clear, k.Quit},
	}
}
