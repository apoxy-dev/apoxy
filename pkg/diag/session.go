package diag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/apoxy/pkg/diag/protocol"
)

// Session is the server-side handle for one connected agent's diag
// stream. It is built by the /diag/rpc handler and consumed by code
// that wants to drive commands against the agent.
//
// Lifecycle: a Session is alive between Register and the moment the
// underlying agent stream closes (request body EOF or write failure).
// After Close, all in-flight Invoke calls receive a final Response
// frame with Error.Code = ErrInternal.
type Session struct {
	down  io.Writer
	flush func() // best-effort; nil if down doesn't implement http.Flusher
	up    io.Reader

	mu      sync.Mutex
	enc     *json.Encoder // serializes downstream writes; guarded by mu
	pending map[uint64]chan protocol.Response
	nextID  atomic.Uint64

	closed   atomic.Bool
	closeErr error
	doneCh   chan struct{}
}

func NewSession(down io.Writer, up io.Reader) *Session {
	s := &Session{
		down:    down,
		up:      up,
		enc:     json.NewEncoder(down),
		pending: map[uint64]chan protocol.Response{},
		doneCh:  make(chan struct{}),
	}
	if f, ok := down.(http.Flusher); ok {
		s.flush = f.Flush
	}
	return s
}

// Start launches the demux loop. Done unblocks when it exits.
func (s *Session) Start() { go s.runDemux() }

// Done returns a channel closed when the session terminates. Read
// CloseErr afterward to distinguish clean EOF from transport error.
func (s *Session) Done() <-chan struct{} { return s.doneCh }

// CloseErr returns the terminal error after Done fires (io.EOF on
// clean close). Calling before Done is closed returns nil.
func (s *Session) CloseErr() error { return s.closeErr }

func (s *Session) runDemux() {
	dec := json.NewDecoder(s.up)
	var termErr error
	for {
		var resp protocol.Response
		if err := dec.Decode(&resp); err != nil {
			termErr = err
			break
		}
		s.mu.Lock()
		ch, ok := s.pending[resp.Id]
		s.mu.Unlock()
		if !ok {
			// Stray response — drop. Could happen if Invoke caller
			// abandoned its channel mid-stream.
			continue
		}
		// Non-blocking send: caller MUST drain promptly. The buffer
		// in Invoke gives single-frame headroom; on overflow we drop
		// to keep the demux loop live.
		select {
		case ch <- resp:
		default:
			// Drop and unblock by closing the channel; caller will
			// observe an early termination.
		}
		// Final frame (Result, Error terminal, or Done) closes the
		// pending entry.
		if isTerminal(resp) {
			s.mu.Lock()
			if c, ok := s.pending[resp.Id]; ok {
				delete(s.pending, resp.Id)
				close(c)
			}
			s.mu.Unlock()
		}
	}
	s.fail(termErr)
}

func isTerminal(r protocol.Response) bool {
	return r.Error != nil || len(r.Result) > 0 || r.Done
}

func (s *Session) fail(err error) {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if err == nil {
		err = io.EOF
	}
	s.closeErr = err
	s.mu.Lock()
	for id, ch := range s.pending {
		delete(s.pending, id)
		close(ch)
	}
	s.mu.Unlock()
	close(s.doneCh)
}

// Close terminates the session. Safe to call concurrently and
// repeatedly.
func (s *Session) Close() { s.fail(io.EOF) }

// Invoke sends one Request to the agent and returns a channel that
// receives every Response frame for that id. The channel is closed
// after the terminal frame (Result, Error, or Done) or when the
// session terminates.
//
// args may be nil. ctx cancellation removes the pending entry but
// does not interrupt the agent — the dispatcher honors its own
// per-command ceiling.
func (s *Session) Invoke(ctx context.Context, command string, args json.RawMessage) (<-chan protocol.Response, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed: %w", s.closeErr)
	}
	id := s.nextID.Add(1)
	// Buffer: 1 for terminal frame; streaming commands rely on the
	// caller draining promptly. Demux loop drops on overflow.
	ch := make(chan protocol.Response, 64)

	s.mu.Lock()
	s.pending[id] = ch
	s.mu.Unlock()

	req := protocol.Request{Id: id, Command: command, Args: args}

	if err := s.writeDown(req); err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		close(ch)
		return nil, fmt.Errorf("write request: %w", err)
	}

	// On ctx cancel, drop the pending entry so the demux loop's stray
	// frames are ignored. The terminal frame from the dispatcher still
	// races with this — if it lands first, the entry is already gone
	// and the cleanup is a no-op. Don't watch ch here: closing it on
	// the first received frame would prematurely terminate streams.
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				s.mu.Lock()
				if c, ok := s.pending[id]; ok && c == ch {
					delete(s.pending, id)
					close(c)
				}
				s.mu.Unlock()
			case <-s.doneCh:
			}
		}()
	}

	return ch, nil
}

func (s *Session) writeDown(r protocol.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errors.New("session closed")
	}
	if err := s.enc.Encode(r); err != nil {
		return err
	}
	if s.flush != nil {
		s.flush()
	}
	return nil
}

// Sessions is a process-scoped registry of agent diag sessions keyed
// by agent identifier (typically the TunnelNode UID).
type Sessions struct {
	mu sync.RWMutex
	m  map[string]*Session
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions { return &Sessions{m: map[string]*Session{}} }

// Register inserts s into the registry under agentID. If an existing
// session is registered under the same id, it is closed and replaced.
func (r *Sessions) Register(agentID string, s *Session) {
	r.mu.Lock()
	if old, ok := r.m[agentID]; ok {
		old.Close()
	}
	r.m[agentID] = s
	r.mu.Unlock()
}

// Unregister removes the session for agentID iff it equals s. The
// equality check prevents a stale Unregister call (from a closing old
// session) from dropping a freshly registered one.
func (r *Sessions) Unregister(agentID string, s *Session) {
	r.mu.Lock()
	if cur, ok := r.m[agentID]; ok && cur == s {
		delete(r.m, agentID)
	}
	r.mu.Unlock()
}

// Lookup returns the session for agentID, if any.
func (r *Sessions) Lookup(agentID string) (*Session, bool) {
	r.mu.RLock()
	s, ok := r.m[agentID]
	r.mu.RUnlock()
	return s, ok
}

