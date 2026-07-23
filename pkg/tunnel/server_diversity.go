package tunnel

// Same-server connection diversity, server side. An agent process that dials
// a server already holding one of its connections is rejected with 409
// Conflict so it re-dials from a fresh UDP 4-tuple, giving the load balancer
// a chance to spread its connections across replicas. See quic.go for the
// protocol constants and the full rationale.

import (
	"log/slog"
	"net/url"
	"sync"
)

// agentConnSlots is the reservation index behind the same-server diversity
// check. It tracks, per "<tunnel UID>/<agent process ID>" key, the connection
// IDs the server holds or is in the middle of establishing for that agent.
// Slots are reserved under the mutex BEFORE the connection becomes visible
// anywhere else, which is what makes the check race-free: two concurrent
// dials from one agent cannot both pass it.
type agentConnSlots struct {
	mu    sync.Mutex
	slots map[string]map[string]struct{}
}

func newAgentConnSlots() *agentConnSlots {
	return &agentConnSlots{slots: make(map[string]map[string]struct{})}
}

// tryAcquire atomically runs the same-server diversity check and, on success,
// reserves a slot for connection cid under the agent's key. The returned
// release must be called when the connection ends (deferred for the handler's
// lifetime); it is never nil.
//
// The request is rejected only when ALL of: the client opted in by sending an
// attempt counter (old clients never did and are never rejected), the attempt
// is not marked final (the client owns "this is my last try" — see
// QueryParamConnFinal), and another connection from the same agent process
// exists that this dial does not declare it replaces.
func (s *agentConnSlots) tryAcquire(tunUID, agentProcessID, cid string, q url.Values) (release func(), ok bool) {
	noop := func() {}
	if agentProcessID == "" {
		// Untrackable client; admit without a reservation.
		return noop, true
	}
	key := tunUID + "/" + agentProcessID
	replaces := q.Get(QueryParamReplacesConnID)

	s.mu.Lock()
	defer s.mu.Unlock()

	if q.Has(QueryParamConnAttempt) && q.Get(QueryParamConnFinal) != "1" {
		for existing := range s.slots[key] {
			if existing != replaces {
				return noop, false
			}
		}
	}

	if s.slots[key] == nil {
		s.slots[key] = make(map[string]struct{})
	}
	s.slots[key][cid] = struct{}{}
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.slots[key], cid)
		if len(s.slots[key]) == 0 {
			delete(s.slots, key)
		}
	}, true
}

// evictReplacedConn force-closes the connection a re-dial declared it
// replaces, so a dead agent connection does not linger (and reject other
// dials) until the QUIC idle timeout. Only the same agent process may evict
// its own connection.
func (t *TunnelServer) evictReplacedConn(replacesID, tunUID, agentProcessID string) {
	if replacesID == "" {
		return
	}
	old, exists := t.conns.Get(replacesID)
	if !exists || old.agentProcessID != agentProcessID || old.obj == nil || string(old.obj.UID) != tunUID {
		return
	}
	slog.Info("Evicting replaced connection", slog.String("connID", replacesID))
	old.cancel()
}
