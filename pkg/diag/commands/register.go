package commands

import "github.com/apoxy-dev/apoxy/pkg/diag"

// RegisterAll registers every built-in diag command into r. The agent
// main calls this once at startup with a fresh registry. New commands
// just add a single line here.
//
// Order does not matter for correctness — Registry sorts the manifest
// — but listing in dependency order helps reviewers see what's new.
func RegisterAll(r *diag.Registry) {
	r.Register(Agent(r))
	r.Register(Clock())
}

// NewDefaultRegistry returns a fresh Registry with every built-in
// command pre-registered. Equivalent to NewRegistry + RegisterAll.
func NewDefaultRegistry() *diag.Registry {
	r := diag.NewRegistry()
	RegisterAll(r)
	return r
}
