package diag_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/diag"
	"github.com/apoxy-dev/apoxy/pkg/diag/protocol"
)

// fakeCmd is a Command whose behavior is controlled per-test.
type fakeCmd struct {
	spec diag.Spec
	run  func(ctx context.Context, args json.RawMessage, e diag.Emitter) (any, error)
}

func (f *fakeCmd) Spec() diag.Spec { return f.spec }
func (f *fakeCmd) Run(ctx context.Context, a json.RawMessage, e diag.Emitter) (any, error) {
	return f.run(ctx, a, e)
}

func TestDispatcher_UnknownCommand(t *testing.T) {
	r := diag.NewRegistry()
	d := diag.New(r)

	down := encodeRequests(t, protocol.Request{Id: 1, Command: "nope"})
	var up bytes.Buffer
	if err := d.Run(context.Background(), down, &up); err != nil {
		t.Fatalf("Run: %v", err)
	}

	resps := decodeResponses(t, &up)
	if len(resps) != 1 || resps[0].Error == nil || resps[0].Error.Code != protocol.ErrUnknownCommand {
		t.Fatalf("expected unknown_command, got %+v", resps)
	}
}

func TestDispatcher_NonStreamingResult(t *testing.T) {
	r := diag.NewRegistry()
	r.Register(&fakeCmd{
		spec: diag.Spec{Name: "echo", CeilingMs: 1000},
		run: func(_ context.Context, args json.RawMessage, _ diag.Emitter) (any, error) {
			return map[string]string{"got": string(args)}, nil
		},
	})

	down := encodeRequests(t, protocol.Request{
		Id: 7, Command: "echo", Args: json.RawMessage(`"hello"`),
	})
	var up bytes.Buffer
	if err := diag.New(r).Run(context.Background(), down, &up); err != nil {
		t.Fatal(err)
	}

	resps := decodeResponses(t, &up)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	if resps[0].Id != 7 || resps[0].Error != nil {
		t.Fatalf("unexpected response: %+v", resps[0])
	}
	var got map[string]string
	if err := json.Unmarshal(resps[0].Result, &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if got["got"] != `"hello"` {
		t.Fatalf("result mismatch: %v", got)
	}
}

func TestDispatcher_Streaming(t *testing.T) {
	r := diag.NewRegistry()
	r.Register(&fakeCmd{
		spec: diag.Spec{Name: "stream", CeilingMs: 1000, Streams: true},
		run: func(_ context.Context, _ json.RawMessage, e diag.Emitter) (any, error) {
			for i := 0; i < 3; i++ {
				if err := e.Chunk(map[string]int{"i": i}); err != nil {
					return nil, err
				}
			}
			return nil, nil // signals streaming-done
		},
	})

	down := encodeRequests(t, protocol.Request{Id: 42, Command: "stream"})
	var up bytes.Buffer
	if err := diag.New(r).Run(context.Background(), down, &up); err != nil {
		t.Fatal(err)
	}

	resps := decodeResponses(t, &up)
	if len(resps) != 4 {
		t.Fatalf("want 3 chunks + 1 done, got %d: %+v", len(resps), resps)
	}
	for i := 0; i < 3; i++ {
		if resps[i].Id != 42 || len(resps[i].Chunk) == 0 {
			t.Fatalf("chunk %d malformed: %+v", i, resps[i])
		}
	}
	if !resps[3].Done || resps[3].Id != 42 {
		t.Fatalf("expected terminal Done, got %+v", resps[3])
	}
}

func TestDispatcher_DeadlineExceeded(t *testing.T) {
	r := diag.NewRegistry()
	r.Register(&fakeCmd{
		spec: diag.Spec{Name: "slow", CeilingMs: 25},
		run: func(ctx context.Context, _ json.RawMessage, _ diag.Emitter) (any, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})

	down := encodeRequests(t, protocol.Request{Id: 1, Command: "slow"})
	var up bytes.Buffer
	d := diag.New(r)
	d.DefaultCeiling = time.Second
	if err := d.Run(context.Background(), down, &up); err != nil {
		t.Fatal(err)
	}

	resps := decodeResponses(t, &up)
	if len(resps) != 1 || resps[0].Error == nil || resps[0].Error.Code != protocol.ErrDeadlineExceeded {
		t.Fatalf("expected deadline_exceeded, got %+v", resps)
	}
}

func TestDispatcher_BusyRejection(t *testing.T) {
	// One command admitted, second rejected. Use a release channel so
	// the first request blocks until we've enqueued the second.
	release := make(chan struct{})
	var entered sync.WaitGroup
	entered.Add(1)

	r := diag.NewRegistry()
	r.Register(&fakeCmd{
		spec: diag.Spec{Name: "block", CeilingMs: 5_000},
		run: func(_ context.Context, _ json.RawMessage, _ diag.Emitter) (any, error) {
			entered.Done()
			<-release
			return "ok", nil
		},
	})

	// Two requests, back-to-back.
	pr, pw := io.Pipe()
	enc := json.NewEncoder(pw)
	go func() {
		if err := enc.Encode(protocol.Request{Id: 1, Command: "block"}); err != nil {
			t.Errorf("encode 1: %v", err)
		}
		entered.Wait() // ensure first command is in-flight before sending second
		if err := enc.Encode(protocol.Request{Id: 2, Command: "block"}); err != nil {
			t.Errorf("encode 2: %v", err)
		}
		close(release)
		_ = pw.Close()
	}()

	d := diag.New(r) // MaxConcurrent=1
	var up bytes.Buffer
	if err := d.Run(context.Background(), pr, &up); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}

	resps := decodeResponses(t, &up)
	// Expect: id=2 busy + id=1 ok. Order between busy reject and the
	// blocked command's eventual completion is unspecified; just check
	// both showed up with the right semantics.
	var sawBusy, sawOK bool
	for _, r := range resps {
		switch r.Id {
		case 2:
			if r.Error != nil && r.Error.Code == protocol.ErrBusy {
				sawBusy = true
			}
		case 1:
			if r.Error == nil && len(r.Result) > 0 {
				sawOK = true
			}
		}
	}
	if !sawBusy || !sawOK {
		t.Fatalf("missing busy or ok response: %+v", resps)
	}
}

// helpers

func encodeRequests(t *testing.T, reqs ...protocol.Request) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range reqs {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	return &buf
}

func decodeResponses(t *testing.T, r io.Reader) []protocol.Response {
	t.Helper()
	var out []protocol.Response
	dec := json.NewDecoder(r)
	for {
		var resp protocol.Response
		if err := dec.Decode(&resp); err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "EOF") {
				return out
			}
			t.Fatalf("decode response: %v", err)
		}
		out = append(out, resp)
	}
}
