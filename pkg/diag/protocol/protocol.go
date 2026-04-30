// Package protocol defines the wire format for the agent diag
// channel: nd-json frames over one long-lived HTTP/3 stream, demuxed
// by Id so multiple commands can interleave.
package protocol

import "encoding/json"

// MimeType is the media type advertised on both halves of the diag
// stream.
const MimeType = "application/x-ndjson"

// Path is the HTTP/3 request path the agent dials on the existing QUIC
// connection to its tunnelproxy.
const Path = "/diag/rpc"

// Request is a single command invocation sent down to the agent.
type Request struct {
	Id      uint64          `json:"id"`
	Command string          `json:"command"`
	Args    json.RawMessage `json:"args,omitempty"`
}

// Response is one frame in the up direction. Exactly one of Result,
// Error, Chunk, or Done is set per frame.
type Response struct {
	Id     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
	Chunk  json.RawMessage `json:"chunk,omitempty"`
	Done   bool            `json:"done,omitempty"`
}

// Error carries a structured failure for a Request. Code is a stable
// short token (e.g. "unknown_command", "invalid_args", "busy",
// "deadline_exceeded"); Message is a human-readable detail.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// Well-known error codes returned by the dispatcher. Commands may
// return their own codes too; these are reserved for transport-level
// failures.
const (
	ErrUnknownCommand   = "unknown_command"
	ErrInvalidArgs      = "invalid_args"
	ErrBusy             = "busy"
	ErrDeadlineExceeded = "deadline_exceeded"
	ErrInternal         = "internal"
)
