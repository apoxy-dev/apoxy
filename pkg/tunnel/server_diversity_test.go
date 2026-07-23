package tunnel

import (
	"net/url"
	"testing"

	"github.com/alphadose/haxmap"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// acquire reserves a slot for cid using query parameters assembled from the
// given attempt/final/replaces values ("" omits the parameter).
func acquire(s *agentConnSlots, tunUID, procID, cid, attempt, final, replaces string) (func(), bool) {
	q := url.Values{}
	if attempt != "" {
		q.Set(QueryParamConnAttempt, attempt)
	}
	if final != "" {
		q.Set(QueryParamConnFinal, final)
	}
	if replaces != "" {
		q.Set(QueryParamReplacesConnID, replaces)
	}
	return s.tryAcquire(tunUID, procID, cid, q)
}

func TestTryAcquireAgentConnSlot(t *testing.T) {
	const (
		tunA  = "11111111-1111-1111-1111-111111111111"
		tunB  = "22222222-2222-2222-2222-222222222222"
		procA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		procB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	)

	// existing describes a pre-reserved slot.
	type existing struct {
		tunUID, procID, cid string
	}

	cases := []struct {
		name     string
		existing []existing
		tunUID   string
		procID   string
		attempt  string
		final    string
		replaces string
		want     bool
	}{
		{
			name:     "rejects when same agent process already holds a slot",
			existing: []existing{{tunA, procA, "c1"}},
			tunUID:   tunA,
			procID:   procA,
			attempt:  "0",
			want:     false,
		},
		{
			name:     "no attempt param (old client) never rejected",
			existing: []existing{{tunA, procA, "c1"}},
			tunUID:   tunA,
			procID:   procA,
			want:     true,
		},
		{
			name:     "final attempt accepted despite existing slot",
			existing: []existing{{tunA, procA, "c1"}},
			tunUID:   tunA,
			procID:   procA,
			attempt:  "2",
			final:    "1",
			want:     true,
		},
		{
			name:     "replaced connection is excluded from the check",
			existing: []existing{{tunA, procA, "c1"}},
			tunUID:   tunA,
			procID:   procA,
			attempt:  "0",
			replaces: "c1",
			want:     true,
		},
		{
			name:     "replacing one conn does not excuse a second",
			existing: []existing{{tunA, procA, "c1"}, {tunA, procA, "c2"}},
			tunUID:   tunA,
			procID:   procA,
			attempt:  "0",
			replaces: "c1",
			want:     false,
		},
		{
			name:     "different agent process on same tunnel accepted",
			existing: []existing{{tunA, procB, "c1"}},
			tunUID:   tunA,
			procID:   procA,
			attempt:  "0",
			want:     true,
		},
		{
			name:     "same agent process on different tunnel accepted",
			existing: []existing{{tunB, procA, "c1"}},
			tunUID:   tunA,
			procID:   procA,
			attempt:  "0",
			want:     true,
		},
		{
			name:    "no existing slots accepted",
			tunUID:  tunA,
			procID:  procA,
			attempt: "0",
			want:    true,
		},
		{
			name:    "empty process ID accepted without reservation",
			tunUID:  tunA,
			procID:  "",
			attempt: "0",
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAgentConnSlots()
			for _, e := range tc.existing {
				_, ok := acquire(srv, e.tunUID, e.procID, e.cid, "", "", "")
				require.True(t, ok, "seeding slot %s must succeed", e.cid)
			}
			release, got := acquire(srv, tc.tunUID, tc.procID, "cid-under-test", tc.attempt, tc.final, tc.replaces)
			require.Equal(t, tc.want, got)
			require.NotNil(t, release, "release must never be nil")
		})
	}
}

// TestTryAcquireAgentConnSlot_ReleaseFreesSlot verifies that releasing a
// reservation makes the slot available again — the property the drain and
// disconnect paths rely on.
func TestTryAcquireAgentConnSlot_ReleaseFreesSlot(t *testing.T) {
	const (
		tun  = "11111111-1111-1111-1111-111111111111"
		proc = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	)

	srv := newAgentConnSlots()

	release1, ok := acquire(srv, tun, proc, "c1", "0", "", "")
	require.True(t, ok)

	_, ok = acquire(srv, tun, proc, "c2", "0", "", "")
	require.False(t, ok, "second dial must be rejected while c1 holds the slot")

	release1()

	release2, ok := acquire(srv, tun, proc, "c2", "0", "", "")
	require.True(t, ok, "slot must be free after release")
	release2()

	require.Empty(t, srv.slots, "released reservations must not leak map entries")
}

// TestTryAcquireAgentConnSlot_ConcurrentDials verifies the reservation is
// atomic: of N simultaneous dials from one agent process, exactly one wins.
func TestTryAcquireAgentConnSlot_ConcurrentDials(t *testing.T) {
	const (
		tun  = "11111111-1111-1111-1111-111111111111"
		proc = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	)

	srv := newAgentConnSlots()

	const dials = 16
	results := make(chan bool, dials)
	for i := 0; i < dials; i++ {
		go func(i int) {
			_, ok := acquire(srv, tun, proc, string(rune('a'+i)), "0", "", "")
			results <- ok
		}(i)
	}

	admitted := 0
	for i := 0; i < dials; i++ {
		if <-results {
			admitted++
		}
	}
	require.Equal(t, 1, admitted, "exactly one concurrent dial must win the slot")
}

func testConn(connID, tunUID, agentProcessID string) *conn {
	return &conn{
		connID:         connID,
		agentProcessID: agentProcessID,
		obj: &corev1alpha.TunnelNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tn-" + tunUID,
				UID:  types.UID(tunUID),
			},
		},
	}
}

// TestEvictReplacedConn verifies eviction only fires for the dialing agent's
// own connection on the same tunnel.
func TestEvictReplacedConn(t *testing.T) {
	const (
		tunA  = "11111111-1111-1111-1111-111111111111"
		tunB  = "22222222-2222-2222-2222-222222222222"
		procA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		procB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	)

	cases := []struct {
		name      string
		conn      *conn
		replaces  string
		tunUID    string
		procID    string
		wantEvict bool
	}{
		{
			name:      "evicts own connection",
			conn:      testConn("c1", tunA, procA),
			replaces:  "c1",
			tunUID:    tunA,
			procID:    procA,
			wantEvict: true,
		},
		{
			name:      "ignores another process's connection",
			conn:      testConn("c1", tunA, procB),
			replaces:  "c1",
			tunUID:    tunA,
			procID:    procA,
			wantEvict: false,
		},
		{
			name:      "ignores another tunnel's connection",
			conn:      testConn("c1", tunB, procA),
			replaces:  "c1",
			tunUID:    tunA,
			procID:    procA,
			wantEvict: false,
		},
		{
			name:      "ignores unknown connection ID",
			conn:      testConn("c1", tunA, procA),
			replaces:  "c-missing",
			tunUID:    tunA,
			procID:    procA,
			wantEvict: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &TunnelServer{conns: haxmap.New[string, *conn]()}
			evicted := false
			tc.conn.cancel = func() { evicted = true }
			srv.conns.Set(tc.conn.connID, tc.conn)

			srv.evictReplacedConn(tc.replaces, tc.tunUID, tc.procID)
			require.Equal(t, tc.wantEvict, evicted)
		})
	}
}
