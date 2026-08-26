package metrics

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// MaxPushBytes caps how much of a pushed metrics body is read. An agent
// exposition body is a few tens of kilobytes, so a body this large is either
// broken or hostile, and the server must not buffer it either way.
const MaxPushBytes = 1 << 20

// DecodePush reads a pushed metrics body in Prometheus text exposition format
// and returns the metric families it holds, keyed by family name. The read is
// capped at MaxPushBytes, so every push handler gets the same limit. A body
// over the cap, or a body that is not the exposition format, comes back as an
// error and the caller answers with 400.
func DecodePush(w http.ResponseWriter, req *http.Request) (map[string]*dto.MetricFamily, error) {
	dec := expfmt.NewDecoder(
		http.MaxBytesReader(w, req.Body, MaxPushBytes),
		expfmt.NewFormat(expfmt.TypeTextPlain),
	)

	families := make(map[string]*dto.MetricFamily)
	for {
		mf := new(dto.MetricFamily)
		if err := dec.Decode(mf); err != nil {
			if errors.Is(err, io.EOF) {
				return families, nil
			}
			return nil, fmt.Errorf("failed to decode the pushed metrics: %w", err)
		}
		families[mf.GetName()] = mf
	}
}
