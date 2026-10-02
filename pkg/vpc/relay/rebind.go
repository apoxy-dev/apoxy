// SPDX-License-Identifier: AGPL-3.0-only

package relay

import "time"

const (
	// movePoll is the time between two reads of the connection address in a watch.
	movePoll = 5 * time.Millisecond
	// moveWait is the time that a watch waits for the connection to move.
	moveWait = 2 * time.Second
)

// watchAddr moves s to the new path of its QUIC connection. QUIC moves the
// connection after it validates the path, so the watch polls for moveWait.
func (r *Router) watchAddr(s *Session) {
	if !s.watching.CompareAndSwap(false, true) {
		return
	}
	from := r.Addr(s)
	go func() {
		defer s.watching.Store(false)
		t := time.NewTicker(movePoll)
		defer t.Stop()
		end := time.Now().Add(moveWait)
		for now := range t.C {
			if a := s.remote(); a.IsValid() && a != from {
				r.mu.Lock()
				if !s.closed {
					r.setAddr(s, a, now)
				}
				r.mu.Unlock()
				return
			}
			if now.After(end) {
				return
			}
		}
	}()
}
