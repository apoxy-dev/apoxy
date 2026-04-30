package diag

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/diag/protocol"
)

// Dispatcher reads Request frames from a downstream reader, runs each
// against its Registry, and writes Response frames to an upstream
// writer. One Dispatcher per agent ↔ tunnelproxy stream.
//
// The dispatcher does not own the transport — the tunnel package opens
// the HTTP/3 stream and hands the read/write halves in. This keeps
// pkg/diag free of any QUIC dependency for testability.
type Dispatcher struct {
	reg *Registry

	// MaxConcurrent caps in-flight commands. Excess Requests get
	// ErrBusy. Default 1 — diag is interactive, not throughput-bound.
	MaxConcurrent int

	// DefaultCeiling is applied to commands whose Spec.CeilingMs is 0.
	DefaultCeiling time.Duration
}

// New returns a Dispatcher backed by r.
func New(r *Registry) *Dispatcher {
	return &Dispatcher{
		reg:            r,
		MaxConcurrent:  1,
		DefaultCeiling: 30 * time.Second,
	}
}

// Run drives the dispatch loop until ctx is cancelled or down returns
// EOF/error. It is safe to call once per stream; concurrent calls on
// the same Dispatcher share the registry but otherwise do not
// interact.
//
// Frames on `down` MUST be Request; frames on `up` are written as
// Response. Both halves use newline-delimited JSON.
func (d *Dispatcher) Run(ctx context.Context, down io.Reader, up io.Writer) error {
	uw := newUpWriter(up)
	dec := json.NewDecoder(down)

	sem := make(chan struct{}, d.MaxConcurrent)
	var wg sync.WaitGroup

	for {
		// Honor cancellation between requests; mid-decode we rely on
		// the underlying transport closing on ctx cancel.
		if err := ctx.Err(); err != nil {
			break
		}
		var req protocol.Request
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			// Malformed frame is fatal for the stream — we have no
			// way to resync nd-json without a framing escape.
			wg.Wait()
			return fmt.Errorf("decode request: %w", err)
		}

		select {
		case sem <- struct{}{}:
		default:
			// Above MaxConcurrent: reject without blocking the loop.
			uw.write(protocol.Response{
				Id:    req.Id,
				Error: &protocol.Error{Code: protocol.ErrBusy, Message: "dispatcher at capacity"},
			})
			continue
		}

		wg.Add(1)
		go func(req protocol.Request) {
			defer wg.Done()
			defer func() { <-sem }()
			d.runOne(ctx, req, uw)
		}(req)
	}

	wg.Wait()
	return nil
}

func (d *Dispatcher) runOne(parent context.Context, req protocol.Request, uw *upWriter) {
	cmd, ok := d.reg.Lookup(req.Command)
	if !ok {
		uw.write(protocol.Response{
			Id:    req.Id,
			Error: &protocol.Error{Code: protocol.ErrUnknownCommand, Message: req.Command},
		})
		return
	}

	ceiling := time.Duration(cmd.Spec().CeilingMs) * time.Millisecond
	if ceiling <= 0 {
		ceiling = d.DefaultCeiling
	}
	ctx, cancel := context.WithTimeout(parent, ceiling)
	defer cancel()

	em := &emitter{id: req.Id, w: uw}
	result, err := cmd.Run(ctx, req.Args, em)
	if err != nil {
		code := protocol.ErrInternal
		if ctx.Err() == context.DeadlineExceeded {
			code = protocol.ErrDeadlineExceeded
		}
		uw.write(protocol.Response{
			Id:    req.Id,
			Error: &protocol.Error{Code: code, Message: err.Error()},
		})
		return
	}

	if result != nil {
		raw, mErr := json.Marshal(result)
		if mErr != nil {
			uw.write(protocol.Response{
				Id:    req.Id,
				Error: &protocol.Error{Code: protocol.ErrInternal, Message: "marshal result: " + mErr.Error()},
			})
			return
		}
		uw.write(protocol.Response{Id: req.Id, Result: raw})
		return
	}

	// Streaming command: emit a terminal Done so the operator end can
	// close out the request id.
	uw.write(protocol.Response{Id: req.Id, Done: true})
}

// upWriter serializes writes to the upstream half so concurrent
// commands don't interleave nd-json frames.
type upWriter struct {
	mu  sync.Mutex
	bw  *bufio.Writer
	enc *json.Encoder
}

func newUpWriter(w io.Writer) *upWriter {
	bw := bufio.NewWriter(w)
	return &upWriter{bw: bw, enc: json.NewEncoder(bw)}
}

func (u *upWriter) write(r protocol.Response) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.enc.Encode(r); err != nil {
		slog.Warn("diag: write response failed", slog.Any("error", err))
		return
	}
	if err := u.bw.Flush(); err != nil {
		slog.Warn("diag: flush response failed", slog.Any("error", err))
	}
}

// emitter is the per-request Emitter handed to streaming commands.
type emitter struct {
	id uint64
	w  *upWriter
}

func (e *emitter) Chunk(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal chunk: %w", err)
	}
	e.w.write(protocol.Response{Id: e.id, Chunk: raw})
	return nil
}
