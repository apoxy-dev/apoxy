// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"cmp"
	"log/slog"
	"slices"
	"time"
)

// The placement of the device: the worker of each RX SPI. A Write that changes the RX entries
// gives each new port session the worker with the least load (on equal loads the lowest number),
// keeps the worker of a port session for a rekey, and publishes the map with its swap. The load of
// a worker is the sum of the receive rates of its port sessions; SampleLoad reads them from the
// receive cells each second. The RX goroutines read the map with no pipeline lock.

// steerMap is the worker of each SPI that has an RX entry.
type steerMap map[uint32]int

// defaultLoad is the load of a port session with no receive rate yet and no port meter rate: 5
// Gbps, in bytes per second.
const defaultLoad = 5e9 / 8

// placed is a port session with a worker, and its receive rate from the samples of its cells.
type placed struct {
	worker int
	cells  []uint32  // Its receive cells at the last sample, in order.
	bytes  []uint64  // The receive bytes of each of the cells at the last sample.
	at     time.Time // The time of the last sample, or zero.
	rate   float64   // Bytes per second, after two samples.
	rated  bool
}

// setWorkers sets the number of workers of the steering map, and publishes the map. With 0 it
// publishes no map, and each packet goes to the default worker.
func (p *Pipeline) setWorkers(n int) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.workers = n
	p.placed = map[portSession]*placed{}
	p.steering.Store(p.place(p.cur))
}

// place gives each new port session of the RX entries of st the worker with the least load, drops
// the port sessions with no RX entry, and returns the steering map of st, or nil with no workers.
// Call it with p.wmu held, after all updates of a Write pass: a failed Write makes no choice.
func (p *Pipeline) place(st *state) *steerMap {
	if p.workers <= 0 {
		return nil
	}
	live := map[portSession]bool{}
	for _, sa := range st.rx {
		live[portSession{sa.port, sa.session}] = true
	}
	for k := range p.placed {
		if !live[k] {
			delete(p.placed, k)
		}
	}
	load := make([]float64, p.workers)
	for k, c := range p.placed {
		load[c.worker] += c.load(st, k)
	}
	var add []portSession
	for k := range live {
		if p.placed[k] == nil {
			add = append(add, k)
		}
	}
	slices.SortFunc(add, func(a, b portSession) int {
		return cmp.Or(cmp.Compare(a.port, b.port), cmp.Compare(a.session, b.session))
	})
	for _, k := range add {
		w := 0
		for i := range load {
			if load[i] < load[w] {
				w = i
			}
		}
		c := &placed{worker: w}
		p.placed[k] = c
		load[w] += c.load(st, k)
		slog.Debug("Gave a relay port session a worker", "port", k.port, "session", k.session, "worker", w, "load", load[w])
	}
	m := make(steerMap, len(st.rx))
	for spi, sa := range st.rx {
		m[spi] = p.placed[portSession{sa.port, sa.session}].worker
	}
	return &m
}

// load returns the receive rate of the port session k in bytes per second. Before it has a rate,
// it returns the rate of its port meter, else defaultLoad.
func (c *placed) load(st *state, k portSession) float64 {
	if c.rated {
		return c.rate
	}
	if pa, ok := st.port(k.port); ok {
		if b := st.meters[meterKey{MeterPort, pa.MeterIndex}]; b != nil {
			return float64(b.cfg.GetCir())
		}
	}
	return defaultLoad
}

// SampleLoad reads the receive cells of each port session that has a worker: its receive rate is
// the bytes since the last sample over the time since then. The key engine of the relay calls it
// each second. A sample gives no rate when the cells of the port session changed or one of their
// counters went down (a MODIFY).
func (p *Pipeline) SampleLoad(now time.Time) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if len(p.placed) == 0 {
		return
	}
	// The receive cell of a classify entry counts its inner bytes in. The tags of a trunk can have
	// one cell, so each cell of a port session counts one time.
	cells := map[portSession][]uint32{}
	for k, e := range p.cur.classify {
		ps := portSession{k.Port, k.Session}
		a, ok := e.action.(ContextAction)
		if ok && p.placed[ps] != nil && !slices.Contains(cells[ps], a.Cell) {
			cells[ps] = append(cells[ps], a.Cell)
		}
	}
	for k, c := range p.placed {
		cs := cells[k]
		slices.Sort(cs)
		bs := make([]uint64, len(cs))
		for i, cell := range cs {
			bs[i] = p.cells[2*cell].bytes.Load()
		}
		if dt := now.Sub(c.at).Seconds(); !c.at.IsZero() && dt > 0 && slices.Equal(cs, c.cells) {
			if n, ok := grown(c.bytes, bs); ok {
				c.rate, c.rated = float64(n)/dt, true
			}
		}
		c.cells, c.bytes, c.at = cs, bs, now
	}
}

// grown returns the sum of the growth of each counter from old to now, or false when one went down.
func grown(old, now []uint64) (uint64, bool) {
	var n uint64
	for i := range now {
		if now[i] < old[i] {
			return 0, false
		}
		n += now[i] - old[i]
	}
	return n, true
}
