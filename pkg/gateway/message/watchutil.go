// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package message

import (
	"github.com/apoxy-dev/apoxy/pkg/log"
	"github.com/telepresenceio/watchable"
)

type Update[K comparable, V any] watchable.Update[K, V]

var logger = log.DefaultLogger

type Metadata struct {
	Runner  string
	Message string
}

// watchable.Map.Subscribe() (or .SubscribeSubset()), and calls the
// given function for each initial value in the map, and for any
// updates.
//
// This is better than simply iterating over snapshot.Updates because
// it handles the case where the watchable.Map already contains
// entries before .Subscribe is called.
func HandleSubscription[K comparable, V any](
	meta Metadata,
	subscription <-chan watchable.Snapshot[K, V],
	handle func(updateFunc Update[K, V], errChans chan error),
) {
	//TODO: find a suitable value
	errChans := make(chan error, 10)
	go func() {
		for err := range errChans {
			logger.With("runner", meta.Runner).Error("Observed an error", "error", err)
		}
	}()

	if snapshot, ok := <-subscription; ok {
		for k, v := range snapshot.State {
			handle(Update[K, V]{
				Key:   k,
				Value: v,
			}, errChans)
		}
	}
	for snapshot := range subscription {
		for _, update := range snapshot.Updates {
			handle(Update[K, V](update), errChans)
		}
	}
}
