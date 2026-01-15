package tui

import (
	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

// TUIPacketObserver implements connection.PacketObserver and sends packets to a channel.
type TUIPacketObserver struct {
	ch      chan<- connection.PacketInfo
	limiter *rate.Limiter
}

// NewPacketObserver creates a new TUI packet observer with rate limiting.
func NewPacketObserver(ch chan<- connection.PacketInfo) *TUIPacketObserver {
	return &TUIPacketObserver{
		ch:      ch,
		limiter: rate.NewLimiter(100, 10), // 100/sec, burst 10
	}
}

// OnPacket is called when a packet is observed.
func (o *TUIPacketObserver) OnPacket(info connection.PacketInfo) {
	if o.limiter.Allow() {
		select {
		case o.ch <- info:
		default:
			// Drop if channel is full
		}
	}
}
