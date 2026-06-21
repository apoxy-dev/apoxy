// SPDX-License-Identifier: AGPL-3.0-only

package workerd

import "testing"

func TestRegistryActiveAndResidentSocket(t *testing.T) {
	r := NewRegistry()
	if r.Active() {
		t.Fatal("empty registry must not be active")
	}
	if got := r.ResidentSocket(); got != "" {
		t.Fatalf("empty resident socket = %q, want \"\"", got)
	}
	r.Upsert(Snapshot{ResidentSocket: "/run/workerd/resident.sock"})
	if !r.Active() {
		t.Fatal("registry with a resident socket must be active")
	}
	if got := r.ResidentSocket(); got != "/run/workerd/resident.sock" {
		t.Fatalf("resident socket = %q", got)
	}
}

func TestRegistryDemuxHeader(t *testing.T) {
	r := NewRegistry()
	r.Upsert(Snapshot{
		ResidentSocket: "/run/workerd/resident.sock",
		Demux: map[string]string{
			"7ce458d7-e20c-443c-aeeb-dbc5663c1240:echo": "echo-r1",
			"7ce458d7-e20c-443c-aeeb-dbc5663c1240:web":  "web-r3",
			// A service exposed but with no live revision must not match.
			"7ce458d7-e20c-443c-aeeb-dbc5663c1240:cold": "",
		},
	})

	cases := []struct {
		name    string
		service string
		want    string
		wantOK  bool
	}{
		{
			name:    "live service yields the project-qualified service key (no revision)",
			service: "echo",
			want:    "7ce458d7-e20c-443c-aeeb-dbc5663c1240:echo",
			wantOK:  true,
		},
		{
			name:    "second live service",
			service: "web",
			want:    "7ce458d7-e20c-443c-aeeb-dbc5663c1240:web",
			wantOK:  true,
		},
		{
			name:    "service with empty live revision does not match",
			service: "cold",
			wantOK:  false,
		},
		{
			name:    "unknown service does not match",
			service: "missing",
			wantOK:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.DemuxHeader(tc.service)
			if ok != tc.wantOK {
				t.Fatalf("DemuxHeader(%q) ok = %v, want %v", tc.service, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Fatalf("DemuxHeader(%q) = %q, want %q", tc.service, got, tc.want)
			}
		})
	}
}

// TestRegistryDemuxHeaderExactServiceSegment guards against a substring/suffix
// match: a service "service" must not match a key whose service is "my-service".
func TestRegistryDemuxHeaderExactServiceSegment(t *testing.T) {
	r := NewRegistry()
	r.Upsert(Snapshot{
		ResidentSocket: "/s.sock",
		Demux:          map[string]string{"proj:my-service": "my-service-r1"},
	})
	if _, ok := r.DemuxHeader("service"); ok {
		t.Fatal("service \"service\" must not match key \"proj:my-service\"")
	}
	if got, ok := r.DemuxHeader("my-service"); !ok || got != "proj:my-service" {
		t.Fatalf("DemuxHeader(my-service) = %q,%v", got, ok)
	}
}

// TestRegistrySetCopiesDemux ensures a caller mutating the map it passed in does
// not race/poison the stored snapshot.
func TestRegistrySetCopiesDemux(t *testing.T) {
	r := NewRegistry()
	in := map[string]string{"proj:echo": "echo-r1"}
	r.Upsert(Snapshot{ResidentSocket: "/s.sock", Demux: in})
	// Deleting the caller's only entry must not drop the stored service.
	delete(in, "proj:echo")
	if got, ok := r.DemuxHeader("echo"); !ok || got != "proj:echo" {
		t.Fatalf("stored demux was mutated by caller: %q,%v", got, ok)
	}
}

// TestRegistryPerNodeAggregate covers the node-keyed registry: each node's row is
// independent, reads aggregate across nodes, re-upsert replaces only that node's
// row, and Delete drops a node.
func TestRegistryPerNodeAggregate(t *testing.T) {
	r := NewRegistry()
	r.Upsert(Snapshot{NodeID: "node-a", ResidentSocket: "/a.sock", Demux: map[string]string{"proj:echo": "echo-r1"}})
	r.Upsert(Snapshot{NodeID: "node-b", ResidentSocket: "/b.sock", Demux: map[string]string{"proj:web": "web-r2"}})

	if !r.Active() {
		t.Fatal("registry with nodes must be active")
	}
	if got, ok := r.DemuxHeader("echo"); !ok || got != "proj:echo" {
		t.Fatalf("DemuxHeader(echo) = %q,%v", got, ok)
	}
	if got, ok := r.DemuxHeader("web"); !ok || got != "proj:web" {
		t.Fatalf("DemuxHeader(web) = %q,%v", got, ok)
	}
	// Re-upserting a node replaces only its row: node-a swaps echo for api, and
	// node-b's web is untouched.
	r.Upsert(Snapshot{NodeID: "node-a", ResidentSocket: "/a.sock", Demux: map[string]string{"proj:api": "api-r1"}})
	if _, ok := r.DemuxHeader("echo"); ok {
		t.Fatal("echo must be gone after node-a re-upsert dropped it")
	}
	if got, ok := r.DemuxHeader("api"); !ok || got != "proj:api" {
		t.Fatalf("after re-upsert DemuxHeader(api) = %q,%v", got, ok)
	}
	if _, ok := r.DemuxHeader("web"); !ok {
		t.Fatal("web on node-b must survive node-a re-upsert")
	}
	// Deleting a node drops its services.
	r.Delete("node-b")
	if _, ok := r.DemuxHeader("web"); ok {
		t.Fatal("web must be gone after node-b delete")
	}
	r.Delete("node-a")
	if r.Active() {
		t.Fatal("registry must be inactive after all nodes removed")
	}
}
