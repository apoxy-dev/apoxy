// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"sync"
	"time"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// meterKey names one meter index.
type meterKey struct {
	id    uint32
	index uint32
}

// bucket is one meter with a configuration. The configuration has cir = pir and cburst = pburst,
// so a meter is one token bucket: green or red.
type bucket struct {
	cfg *p4.MeterConfig

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newBucket(cfg *p4.MeterConfig) (*bucket, error) {
	switch {
	case cfg.GetCir() < 0 || cfg.GetCburst() < 0:
		return nil, status.Error(codes.InvalidArgument, "the meter rate and burst must not be negative")
	case cfg.GetCir() != cfg.GetPir() || cfg.GetCburst() != cfg.GetPburst():
		return nil, status.Error(codes.InvalidArgument, "the meter must have cir = pir and cburst = pburst")
	case cfg.GetEburst() != 0:
		return nil, status.Error(codes.InvalidArgument, "the meter has no eburst")
	}
	return &bucket{cfg: proto.Clone(cfg).(*p4.MeterConfig), tokens: float64(cfg.GetCburst())}, nil
}

// take reports whether n units are green at now, and takes them.
func (b *bucket) take(n int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		b.tokens += now.Sub(b.last).Seconds() * float64(b.cfg.GetCir())
	}
	b.tokens = min(b.tokens, float64(b.cfg.GetCburst()))
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// meterIndex checks the meter ID and index of a MeterEntry.
func meterIndex(me *p4.MeterEntry) (meterKey, error) {
	size, ok := meterSizes[me.GetMeterId()]
	if !ok {
		return meterKey{}, status.Errorf(codes.NotFound, "unknown meter %d", me.GetMeterId())
	}
	if me.GetIndex() == nil {
		return meterKey{}, status.Error(codes.InvalidArgument, "the meter entry has no index")
	}
	if i := me.GetIndex().GetIndex(); i < 0 || i >= size {
		return meterKey{}, status.Errorf(codes.OutOfRange, "meter index %d is out of range", i)
	}
	return meterKey{me.GetMeterId(), uint32(me.GetIndex().GetIndex())}, nil
}

// writeMeter applies a MODIFY of a meter to the copy. No configuration means no limit. A new
// configuration gets a new bucket; the copy shares the buckets of the other meters.
func (c *change) writeMeter(typ p4.Update_Type, me *p4.MeterEntry) error {
	if typ != p4.Update_MODIFY {
		return status.Error(codes.InvalidArgument, "a meter takes only MODIFY")
	}
	k, err := meterIndex(me)
	if err != nil {
		return err
	}
	if me.GetConfig() == nil {
		if _, ok := c.st.meters[k]; ok {
			delete(own(&c.st.meters, &c.meters), k)
		}
		return nil
	}
	b, err := newBucket(me.GetConfig())
	if err != nil {
		return err
	}
	own(&c.st.meters, &c.meters)[k] = b
	return nil
}

// readMeters gives the meter entries that match me. With no index, it gives the configured ones.
func (s *state) readMeters(me *p4.MeterEntry, out *[]*p4.Entity) error {
	if me.GetIndex() != nil {
		k, err := meterIndex(me)
		if err != nil {
			return err
		}
		*out = append(*out, meterEntity(k, s.meters[k]))
		return nil
	}
	if _, ok := meterSizes[me.GetMeterId()]; !ok && me.GetMeterId() != 0 {
		return status.Errorf(codes.NotFound, "unknown meter %d", me.GetMeterId())
	}
	for k, b := range s.meters {
		if me.GetMeterId() == 0 || me.GetMeterId() == k.id {
			*out = append(*out, meterEntity(k, b))
		}
	}
	return nil
}

func meterEntity(k meterKey, b *bucket) *p4.Entity {
	e := &p4.MeterEntry{MeterId: k.id, Index: &p4.Index{Index: int64(k.index)}}
	if b != nil {
		e.Config = proto.Clone(b.cfg).(*p4.MeterConfig)
	}
	return &p4.Entity{Entity: &p4.Entity_MeterEntry{MeterEntry: e}}
}
