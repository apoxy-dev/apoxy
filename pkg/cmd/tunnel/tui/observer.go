package tui

import (
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

const autoSuspendThreshold = 500 // packets per second

// TUIPacketObserver implements connection.PacketObserver and sends packets to a channel.
type TUIPacketObserver struct {
	ch      chan<- connection.PacketInfo
	limiter *rate.Limiter

	suspended     atomic.Bool
	autoSuspended atomic.Bool
	packetCount   atomic.Int64
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
	o.packetCount.Add(1)
	if o.suspended.Load() {
		return
	}
	if o.limiter.Allow() {
		select {
		case o.ch <- info:
		default:
			// Drop if channel is full
		}
	}
}

// IsSuspended returns whether the observer is suspended.
func (o *TUIPacketObserver) IsSuspended() bool {
	return o.suspended.Load()
}

// CountPacket increments the packet counter without processing.
// Called by splice.go when suspended, to track rate.
func (o *TUIPacketObserver) CountPacket() {
	o.packetCount.Add(1)
}

// Suspend stops packet observation.
func (o *TUIPacketObserver) Suspend() {
	o.suspended.Store(true)
}

// Resume resumes packet observation.
func (o *TUIPacketObserver) Resume() {
	o.suspended.Store(false)
	o.autoSuspended.Store(false)
}

// IsAutoSuspended returns whether suspension was triggered automatically.
func (o *TUIPacketObserver) IsAutoSuspended() bool {
	return o.autoSuspended.Load()
}

// CheckAutoSuspend reads and resets the packet counter, computes rate,
// and auto-suspends if the rate exceeds the threshold.
// Should be called periodically (e.g. every 500ms from the TUI tick).
func (o *TUIPacketObserver) CheckAutoSuspend(window time.Duration) (pps int64, didAutoSuspend bool) {
	count := o.packetCount.Swap(0)
	pps = int64(float64(count) / window.Seconds())

	if !o.suspended.Load() && pps > autoSuspendThreshold {
		o.autoSuspended.Store(true)
		o.suspended.Store(true)
		return pps, true
	}
	return pps, false
}
