package metrics

import (
	"testing"
	"time"
)

func TestTunnelBacklogTotals(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name        string
		set         map[string]backlog
		deleted     []string
		wantCreates int
		wantAge     time.Duration
	}{
		{name: "empty"},
		{
			name: "sum of creates and the oldest write",
			set: map[string]backlog{
				"a": {creates: 2, oldest: now.Add(-3 * time.Second)},
				"b": {creates: 1, oldest: now.Add(-10 * time.Second)},
			},
			wantCreates: 3,
			wantAge:     10 * time.Second,
		},
		{
			name: "an owner with nothing waiting has no age",
			set: map[string]backlog{
				"a": {},
				"b": {creates: 1, oldest: now.Add(-time.Second)},
			},
			wantCreates: 1,
			wantAge:     time.Second,
		},
		{
			name: "a deleted owner is not counted",
			set: map[string]backlog{
				"a": {creates: 4, oldest: now.Add(-time.Minute)},
				"b": {creates: 1, oldest: now.Add(-time.Second)},
			},
			deleted:     []string{"a"},
			wantCreates: 1,
			wantAge:     time.Second,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &tunnelBacklog{byOwner: make(map[any]backlog)}
			for owner, l := range tc.set {
				b.byOwner[owner] = l
			}
			for _, owner := range tc.deleted {
				delete(b.byOwner, owner)
			}
			creates, age := b.totals(now)
			if creates != tc.wantCreates || age != tc.wantAge {
				t.Fatalf("totals() = %d, %s, want %d, %s", creates, age, tc.wantCreates, tc.wantAge)
			}
		})
	}
}

func TestSetTunnelBacklog(t *testing.T) {
	owner := new(int)
	SetTunnelBacklog(owner, 3, time.Now().Add(-time.Second))
	backlogs.mu.Lock()
	got := backlogs.byOwner[owner]
	backlogs.mu.Unlock()
	if got.creates != 3 {
		t.Fatalf("creates = %d, want 3", got.creates)
	}
	DeleteTunnelBacklog(owner)
	backlogs.mu.Lock()
	_, ok := backlogs.byOwner[owner]
	backlogs.mu.Unlock()
	if ok {
		t.Fatal("DeleteTunnelBacklog left the owner")
	}
}
