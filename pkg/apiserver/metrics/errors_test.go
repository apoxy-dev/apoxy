package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	metricsv1alpha1 "github.com/apoxy-dev/apoxy/api/metrics/v1alpha1"
)

// TestToStatusError has one row per status in the design's error table, so a
// new mapping cannot land without a row here.
func TestToStatusError(t *testing.T) {
	gr := metricsv1alpha1.Resource("metrics")

	cases := []struct {
		name     string
		err      error
		wantCode int
		wantMsg  string
		// wantHidden is text that must NOT reach the client, such as the
		// compiled SQL or the raw backend message.
		wantHidden string
	}{
		{
			name:     "concurrency cap is 429",
			err:      TooManyRequests(),
			wantCode: http.StatusTooManyRequests,
			wantMsg:  "too many concurrent metrics reads",
		},
		{
			name:     "guardrail violation is 400",
			err:      BadRequest("invalid scopeKind %q: want one of %s", "Widget", "Project, Gateway"),
			wantCode: http.StatusBadRequest,
			wantMsg:  "want one of Project, Gateway",
		},
		{
			name:     "a recipe that does not compile is 422",
			err:      Unprocessable("metric %q cannot be evaluated: unknown field", "v2.errors"),
			wantCode: http.StatusUnprocessableEntity,
			wantMsg:  "cannot be evaluated",
		},
		{
			name:       "an unreachable backend is 503",
			err:        Unavailable(errors.New("dial tcp 10.0.0.1:9000: connect: connection refused")),
			wantCode:   http.StatusServiceUnavailable,
			wantMsg:    "metrics backend unavailable",
			wantHidden: "connection refused",
		},
		{
			name:     "a missing owner is 404",
			err:      NotFound(gr, "prod"),
			wantCode: http.StatusNotFound,
			wantMsg:  "not found",
		},
		{
			name:     "no backend configured is 501 naming the flags",
			err:      NotImplemented("--clickhouse_addr", "--clickhouse_database"),
			wantCode: http.StatusNotImplemented,
			wantMsg:  "--clickhouse_addr",
		},
		{
			name:       "a timed-out read is 503, not 500",
			err:        fmt.Errorf("read rollup: %w", context.DeadlineExceeded),
			wantCode:   http.StatusServiceUnavailable,
			wantMsg:    "metrics backend unavailable",
			wantHidden: "read rollup",
		},
		{
			name:       "an unclassified error hides its cause",
			err:        errors.New("SELECT countMerge(requests) FROM otel.http_1m_ab12cd34 WHERE gateway = 'prod'"),
			wantCode:   http.StatusInternalServerError,
			wantMsg:    "internal metrics read error",
			wantHidden: "otel.http_1m_ab12cd34",
		},
		{
			name:     "an apimachinery status passes through",
			err:      apierrors.NewConflict(gr, "http.requests", errors.New("stale")),
			wantCode: http.StatusConflict,
			wantMsg:  "http.requests",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := ToStatusError("series", tc.err)
			var statusErr *apierrors.StatusError
			if !errors.As(status, &statusErr) {
				t.Fatalf("mapped error is not a Status: %T", status)
			}
			if got := int(statusErr.ErrStatus.Code); got != tc.wantCode {
				t.Errorf("code = %d, want %d", got, tc.wantCode)
			}
			if got := StatusCode(tc.err); got != tc.wantCode {
				t.Errorf("StatusCode = %d, want %d", got, tc.wantCode)
			}
			body := statusErr.ErrStatus.String()
			if !strings.Contains(body, tc.wantMsg) {
				t.Errorf("status = %q, want it to contain %q", body, tc.wantMsg)
			}
			if tc.wantHidden != "" && strings.Contains(body, tc.wantHidden) {
				t.Errorf("status leaks %q: %s", tc.wantHidden, body)
			}
		})
	}
}

// TestTooManyRequestsCarriesRetryAfter checks the one header the 429 row of the
// table promises.
func TestTooManyRequestsCarriesRetryAfter(t *testing.T) {
	status := ToStatusError("series", TooManyRequests())
	var statusErr *apierrors.StatusError
	if !errors.As(status, &statusErr) {
		t.Fatalf("mapped error is not a Status: %T", status)
	}
	if statusErr.ErrStatus.Details == nil || statusErr.ErrStatus.Details.RetryAfterSeconds <= 0 {
		t.Fatalf("429 carries no Retry-After: %+v", statusErr.ErrStatus.Details)
	}
}
