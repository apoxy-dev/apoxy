// Package diag implements the agent-side debug surface that runs over
// the existing QUIC control channel to tunnelproxy.
package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

func sortSpecs(s []Spec) {
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
}

// ArgType is the wire-format token for an argument's type.
type ArgType string

const (
	ArgTypeString   ArgType = "string"
	ArgTypeInt      ArgType = "int"
	ArgTypeBool     ArgType = "bool"
	ArgTypeDuration ArgType = "duration"
)

// ArgSpec describes one argument of a Command. It is serialized into
// the manifest returned by the built-in `agent` command so an operator
// can discover the surface with a single GET.
type ArgSpec struct {
	Type     ArgType `json:"type"`
	Required bool    `json:"required,omitempty"`
	Default  any     `json:"default,omitempty"`
	Max      any     `json:"max,omitempty"`
	Min      any     `json:"min,omitempty"`
	Desc     string  `json:"description,omitempty"`
}

// Spec is the manifest entry for a single Command.
type Spec struct {
	Name      string             `json:"name"`
	Desc      string             `json:"description,omitempty"`
	Args      map[string]ArgSpec `json:"args,omitempty"`
	Streams   bool               `json:"streams,omitempty"`
	CeilingMs int                `json:"ceiling_ms"`
}

// Emitter is what a streaming Command writes its chunks to. It is
// supplied by the dispatcher; Commands MUST NOT retain a reference
// past their Run call.
type Emitter interface {
	// Chunk emits one streaming frame upstream.
	Chunk(v any) error
}

// Command is the contract every probe implements. Non-streaming
// commands return a JSON-serializable Result and ignore the Emitter.
// Streaming commands return Result == nil and emit chunks via e until
// Run returns.
type Command interface {
	// Spec returns the manifest entry for this command. It is called
	// once at registration; the result must be safe to share.
	Spec() Spec

	// Run executes the command. args is the raw `args` field from the
	// Request; implementations decode it as needed. ctx carries the
	// dispatcher-imposed wall-clock ceiling and is cancelled when the
	// stream goes away.
	Run(ctx context.Context, args json.RawMessage, e Emitter) (result any, err error)
}

// Registry holds the set of registered commands. It is built once at
// startup and treated as immutable thereafter.
type Registry struct {
	cmds map[string]Command
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{cmds: map[string]Command{}} }

// Register adds c to r. Panics on duplicate name — registration is a
// startup-time operation.
func (r *Registry) Register(c Command) {
	name := c.Spec().Name
	if _, ok := r.cmds[name]; ok {
		panic(fmt.Sprintf("diag: duplicate command %q", name))
	}
	r.cmds[name] = c
}

// Lookup returns the command with the given name and whether it
// exists.
func (r *Registry) Lookup(name string) (Command, bool) {
	c, ok := r.cmds[name]
	return c, ok
}

// Specs returns the manifest entries for every registered command,
// sorted by name. Used by the built-in `agent` command.
func (r *Registry) Specs() []Spec {
	out := make([]Spec, 0, len(r.cmds))
	for _, c := range r.cmds {
		out = append(out, c.Spec())
	}
	// Stable order so manifest diffs are reviewable.
	sortSpecs(out)
	return out
}
