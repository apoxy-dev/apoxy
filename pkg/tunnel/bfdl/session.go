package bfdl

import (
	"sync"
	"time"
)

// OnStateChangeFunc is called when a BFD session transitions between states.
type OnStateChangeFunc func(old, new State)

// Session implements the BFD-lite state machine (RFC 5880 section 6.8.6, simplified).
// It supports three states: Down, Init, and Up.
type Session struct {
	mu          sync.Mutex
	localDiscr  uint32
	remoteDiscr uint32
	localState  State
	remoteState State
	detectMult  uint8
	txInterval  time.Duration
	lastRx      time.Time

	onStateChange OnStateChangeFunc
}

// NewSession creates a new BFD session starting in Down state.
func NewSession(localDiscr uint32, detectMult uint8, txInterval time.Duration) *Session {
	return &Session{
		localDiscr: localDiscr,
		detectMult: detectMult,
		txInterval: txInterval,
		localState: StateDown,
	}
}

// SetOnStateChange sets the callback for state transitions.
func (s *Session) SetOnStateChange(fn OnStateChangeFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStateChange = fn
}

// ProcessRx handles an incoming BFD packet and writes the response into resp.
//
// Simplified RFC 5880 section 6.8.6 state transitions:
//
//	Local=Down  + Remote=Down  -> Init
//	Local=Down  + Remote=Init  -> Up
//	Local=Init  + Remote=Init  -> Up
//	Local=Init  + Remote=Up    -> Up
//	Local=Up    + Remote=Down  -> Down
func (s *Session) ProcessRx(rx, resp *Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastRx = time.Now()
	s.remoteDiscr = rx.MyDiscr
	s.remoteState = rx.State

	oldState := s.localState
	switch s.localState {
	case StateDown:
		switch rx.State {
		case StateDown:
			s.localState = StateInit
		case StateInit:
			s.localState = StateUp
		}
	case StateInit:
		switch rx.State {
		case StateInit, StateUp:
			s.localState = StateUp
		}
	case StateUp:
		if rx.State == StateDown || rx.State == StateAdminDown {
			s.localState = StateDown
		}
	}

	if oldState != s.localState && s.onStateChange != nil {
		s.onStateChange(oldState, s.localState)
	}

	if resp != nil {
		s.buildTxLocked(resp)
	}
}

// BuildTx writes an outgoing BFD control packet into pkt for periodic
// transmission.
func (s *Session) BuildTx(pkt *Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buildTxLocked(pkt)
}

func (s *Session) buildTxLocked(pkt *Packet) {
	*pkt = Packet{
		Version:       1,
		State:         s.localState,
		DetectMult:    s.detectMult,
		MyDiscr:       s.localDiscr,
		YourDiscr:     s.remoteDiscr,
		DesiredMinTx:  uint32(s.txInterval.Microseconds()),
		RequiredMinRx: uint32(s.txInterval.Microseconds()),
	}
}

// State returns the current session state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localState
}

// Expired returns true if the detect timer has expired
// (no Rx within detectMult * txInterval).
func (s *Session) Expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastRx.IsZero() {
		return false // No packets received yet, not expired.
	}
	detectTime := time.Duration(s.detectMult) * s.txInterval
	return time.Since(s.lastRx) > detectTime
}

// AdminDown transitions the session to AdminDown state. This signals the
// remote peer that this session is being intentionally shut down (e.g.,
// during graceful drain). The remote peer should transition to Down.
func (s *Session) AdminDown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldState := s.localState
	if oldState == StateAdminDown {
		return
	}
	s.localState = StateAdminDown
	if s.onStateChange != nil {
		s.onStateChange(oldState, StateAdminDown)
	}
}

// LastRx returns when the last valid BFD packet was received.
func (s *Session) LastRx() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRx
}
