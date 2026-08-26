package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// exactlyAtCapBody builds a valid exposition body of exactly MaxPushBytes
// bytes, padded to length with a comment line.
func exactlyAtCapBody(t *testing.T) string {
	t.Helper()

	const line = "tunnel_relay_rtt_seconds{relay=\"relay-a\"} 0.012\n"
	body := strings.Repeat(line, MaxPushBytes/len(line))
	pad := MaxPushBytes - len(body)
	if pad < 3 {
		t.Fatalf("the padding of %d bytes is too small for a comment line", pad)
	}
	// A comment line is "# ", the padding, and the newline.
	return body + "# " + strings.Repeat("p", pad-3) + "\n"
}

// TestDecodePush pins how a pushed body is read: a well formed body gives back
// its families, a body of exactly the cap is still accepted, a body over the
// cap reports ErrPushTooLarge so the handler can answer 413, and a body that is
// simply not the exposition format is never classed as too large.
func TestDecodePush(t *testing.T) {
	const metricsBody = "# TYPE tunnel_relay_rtt_seconds gauge\n" +
		"tunnel_relay_rtt_seconds{relay=\"relay-a\"} 0.012\n"

	cases := []struct {
		name string
		body string
		// wantErr is true when the decode must fail.
		wantErr bool
		// wantTooLarge is true when the failure must wrap ErrPushTooLarge.
		wantTooLarge bool
		// wantFamily is the family name the result must hold, if any.
		wantFamily string
	}{
		{
			name:       "a well formed body gives back its families",
			body:       metricsBody,
			wantFamily: "tunnel_relay_rtt_seconds",
		},
		{
			name: "an empty body gives back no families",
			body: "",
		},
		{
			name:    "a body that is not the exposition format is rejected",
			body:    "this is not the exposition format\n",
			wantErr: true,
		},
		{
			name:       "a body of exactly the cap is accepted",
			body:       exactlyAtCapBody(t),
			wantFamily: "tunnel_relay_rtt_seconds",
		},
		{
			name:         "a body over the cap reports the size limit",
			body:         exactlyAtCapBody(t) + "tunnel_relay_rtt_seconds{relay=\"relay-b\"} 0.5\n",
			wantErr:      true,
			wantTooLarge: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/metrics/push", strings.NewReader(tc.body))
			families, err := DecodePush(httptest.NewRecorder(), req)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("decode of %d bytes succeeded, want an error", len(tc.body))
				}
				if got := errors.Is(err, ErrPushTooLarge); got != tc.wantTooLarge {
					t.Fatalf("errors.Is(err, ErrPushTooLarge) = %v, want %v (err = %v)",
						got, tc.wantTooLarge, err)
				}
				if families != nil {
					t.Errorf("a failed decode gave back %d families, want none", len(families))
				}
				return
			}

			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if tc.wantFamily == "" {
				if len(families) != 0 {
					t.Fatalf("decode gave back %d families, want none", len(families))
				}
				return
			}
			if _, ok := families[tc.wantFamily]; !ok {
				t.Fatalf("decode gave back %v, want %q", families, tc.wantFamily)
			}
		})
	}
}
