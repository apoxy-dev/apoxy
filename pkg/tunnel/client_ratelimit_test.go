package tunnel

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrRateLimited_Error(t *testing.T) {
	t.Run("with retry-after", func(t *testing.T) {
		e := &ErrRateLimited{RetryAfter: 7 * time.Second}
		assert.Equal(t, "tunnel dial rate-limited: retry after 7s", e.Error())
	})
	t.Run("without retry-after", func(t *testing.T) {
		e := &ErrRateLimited{}
		assert.Equal(t, "tunnel dial rate-limited", e.Error())
	})
}

func TestErrRateLimited_IsRecognizable(t *testing.T) {
	// Callers use errors.As to extract RetryAfter without depending on
	// string matching. This test locks in that contract.
	var target *ErrRateLimited
	err := error(&ErrRateLimited{RetryAfter: 3 * time.Second})
	require.True(t, errors.As(err, &target))
	assert.Equal(t, 3*time.Second, target.RetryAfter)
}

func TestParseRetryAfterHeader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{"empty", "", 0},
		{"zero seconds", "0", 0}, // 0 duration but still parsed — treated as "immediate retry allowed"
		{"plain integer seconds", "5", 5 * time.Second},
		{"large integer", "3600", time.Hour},
		{"negative integer rejected", "-5", 0},
		{"non-numeric garbage", "soon", 0},
		{"decimal not supported (Retry-After is seconds integer or HTTP-date only)", "1.5", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseRetryAfterHeader(tt.input))
		})
	}
}

// TestParseRetryAfterHeader_HTTPDate covers the HTTP-date fallback. We don't
// assert the exact duration because it depends on wall time; instead we
// assert the returned value is close to the expected offset and non-zero.
func TestParseRetryAfterHeader_HTTPDate(t *testing.T) {
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	got := parseRetryAfterHeader(future)
	assert.Greater(t, got, 25*time.Second)
	assert.LessOrEqual(t, got, 31*time.Second)

	// A date in the past returns 0 — no point waiting.
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	assert.Zero(t, parseRetryAfterHeader(past))
}

// TestParseRetryAfterHeader_FromRealResponse exercises the same read path the
// client uses in Dial: rsp.Header.Get("Retry-After"). Ensures we aren't
// subtly mis-handling the header's canonical casing.
func TestParseRetryAfterHeader_FromRealResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	rsp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer rsp.Body.Close()

	got := parseRetryAfterHeader(rsp.Header.Get("Retry-After"))
	assert.Equal(t, 12*time.Second, got)
}
