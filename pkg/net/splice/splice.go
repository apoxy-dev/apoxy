// Package splice copies data between two connections in both directions.
package splice

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/dpeckett/contextio"
	"golang.org/x/sync/errgroup"
)

// settleDelay lets the other direction drain before it is cancelled.
const settleDelay = 10 * time.Millisecond

// Splice copies data between a and b in both directions until one side ends.
func Splice(ctx context.Context, a, b contextio.DeadlineReadWriter) (int64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var written atomic.Int64
	copyDirection := func(dst contextio.DeadlineWriter, src contextio.DeadlineReader) func() error {
		return func() error {
			defer func() {
				time.Sleep(settleDelay)
				cancel()
			}()
			n, err := contextio.CopyContext(ctx, dst, src, nil)
			written.Add(n)
			return err
		}
	}

	var g errgroup.Group
	g.Go(copyDirection(a, b))
	g.Go(copyDirection(b, a))

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return written.Load(), err
	}
	return written.Load(), nil
}
