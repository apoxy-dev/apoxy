// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"cmp"
	"log/slog"
	"slices"
)

// The steering of the device: the worker of each RX SPI. Each Write that passes gives each new
// port session of an RX entry the worker with the fewest port sessions (on equal counts the lowest
// number), keeps the worker of a port session for a rekey, and publishes the map. The RX goroutines
// read the map with no pipeline lock.

// steerMap is the worker of each SPI that has an RX entry.
type steerMap map[uint32]int

// setWorkers sets the number of workers of the steering map, and publishes the map. With 0 it
// publishes no map, and each packet goes to the default worker.
func (p *Pipeline) setWorkers(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.workers = n
	p.workerOf = map[portSession]int{}
	p.steer()
}

// steer places the new port sessions of the RX entries and publishes the steering map. Call it
// with p.mu held for writing.
func (p *Pipeline) steer() {
	if p.workers <= 0 {
		p.steering.Store(nil)
		return
	}
	live := map[portSession]bool{}
	for _, sa := range p.st.rx {
		live[portSession{sa.port, sa.session}] = true
	}
	for k := range p.workerOf {
		if !live[k] {
			delete(p.workerOf, k)
		}
	}
	count := make([]int, p.workers)
	for _, w := range p.workerOf {
		count[w]++
	}
	var add []portSession
	for k := range live {
		if _, ok := p.workerOf[k]; !ok {
			add = append(add, k)
		}
	}
	slices.SortFunc(add, func(a, b portSession) int {
		return cmp.Or(cmp.Compare(a.port, b.port), cmp.Compare(a.session, b.session))
	})
	for _, k := range add {
		w := 0
		for i := range count {
			if count[i] < count[w] {
				w = i
			}
		}
		p.workerOf[k] = w
		count[w]++
		slog.Debug("Gave a relay port session a worker", "port", k.port, "session", k.session, "worker", w)
	}
	m := make(steerMap, len(p.st.rx))
	for spi, sa := range p.st.rx {
		m[spi] = p.workerOf[portSession{sa.port, sa.session}]
	}
	p.steering.Store(&m)
}
