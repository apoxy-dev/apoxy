// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"net/netip"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Index limits of the action parameters: a cell c uses the counter indices 2c and 2c+1, and port
// meter i uses lane meters 4i to 4i+3.
const (
	maxCell  = 1 << 20
	maxMeter = 1 << 16
)

// entry is one table entry. vpc is the number of the VPC name of a classify action or a route key.
type entry[K comparable] struct {
	key    K
	action Action
	md     []byte
	vpc    uint32
}

// setKey names the source entries of one port session and tag.
type setKey struct {
	port, session uint64
	tag           uint32
}

// nameRef is the number of a VPC name and the count of the entries that use it.
type nameRef struct {
	num  uint32
	refs int
}

// state is the content of the tables and the keys. Write changes it with the lock held; the
// packets read it with the read lock held.
type state struct {
	ports    map[uint64]*entry[PortsKey]
	classify map[ClassifyKey]*entry[ClassifyKey]
	source   map[setKey]*lpm[*entry[SourceKey]]
	route    map[uint32]*lpm[*entry[RouteKey]]
	names    map[string]*nameRef
	free     []uint32
	nextName uint32
	rx       map[uint32]*rxSA
	tx       map[portSession]*txLanes
	meters   map[meterKey]*bucket
}

func newState() state {
	return state{
		ports:    map[uint64]*entry[PortsKey]{},
		classify: map[ClassifyKey]*entry[ClassifyKey]{},
		source:   map[setKey]*lpm[*entry[SourceKey]]{},
		route:    map[uint32]*lpm[*entry[RouteKey]]{},
		names:    map[string]*nameRef{},
		rx:       map[uint32]*rxSA{},
		tx:       map[portSession]*txLanes{},
		meters:   map[meterKey]*bucket{},
	}
}

// txn records how to undo each change of one Write.
type txn struct {
	undo []func()
}

func (t *txn) onUndo(f func()) { t.undo = append(t.undo, f) }

func (t *txn) rollback() {
	for i := len(t.undo) - 1; i >= 0; i-- {
		t.undo[i]()
	}
	t.undo = nil
}

func set[K comparable, V any](t *txn, m map[K]V, k K, v V) {
	old, had := m[k]
	m[k] = v
	t.onUndo(func() {
		if had {
			m[k] = old
		} else {
			delete(m, k)
		}
	})
}

func del[K comparable, V any](t *txn, m map[K]V, k K) {
	old, had := m[k]
	if !had {
		return
	}
	delete(m, k)
	t.onUndo(func() { m[k] = old })
}

// lpm is a longest-prefix match on 128-bit addresses. IPv4 is IPv4-mapped.
type lpm[V any] struct {
	m    map[netip.Prefix]V
	lens [129]int
}

func newLPM[V any]() *lpm[V] { return &lpm[V]{m: map[netip.Prefix]V{}} }

func (l *lpm[V]) lookup(a netip.Addr) (V, bool) {
	for n := 128; n >= 0; n-- {
		if l.lens[n] == 0 {
			continue
		}
		p, _ := a.Prefix(n)
		if v, ok := l.m[p]; ok {
			return v, true
		}
	}
	var zero V
	return zero, false
}

func (l *lpm[V]) put(t *txn, p netip.Prefix, v V) {
	if _, had := l.m[p]; !had {
		n := p.Bits()
		l.lens[n]++
		t.onUndo(func() { l.lens[n]-- })
	}
	set(t, l.m, p, v)
}

func (l *lpm[V]) remove(t *txn, p netip.Prefix) {
	if _, had := l.m[p]; !had {
		return
	}
	n := p.Bits()
	l.lens[n]--
	t.onUndo(func() { l.lens[n]++ })
	del(t, l.m, p)
}

// ref gives the number of a VPC name and counts one more entry that uses it.
func (s *state) ref(t *txn, name string) uint32 {
	r := s.names[name]
	if r == nil {
		r = &nameRef{}
		if n := len(s.free); n > 0 {
			r.num = s.free[n-1]
			s.free = s.free[:n-1]
			t.onUndo(func() { s.free = append(s.free, r.num) })
		} else {
			s.nextName++
			r.num = s.nextName
			t.onUndo(func() { s.nextName-- })
		}
		set(t, s.names, name, r)
	}
	r.refs++
	t.onUndo(func() { r.refs-- })
	return r.num
}

// unref counts one less entry that uses a VPC name, and frees its number after the last one.
func (s *state) unref(t *txn, name string) {
	r := s.names[name]
	if r == nil {
		return
	}
	r.refs--
	t.onUndo(func() { r.refs++ })
	if r.refs == 0 {
		del(t, s.names, name)
		s.free = append(s.free, r.num)
		t.onUndo(func() { s.free = s.free[:len(s.free)-1] })
	}
}

// vpcName returns the VPC name of an action, or "".
func vpcName(a Action) string {
	if c, ok := a.(ContextAction); ok {
		return c.VPC
	}
	return ""
}

// checkAction checks the indices of the action parameters.
func checkAction(a Action) error {
	switch a := a.(type) {
	case PortAction:
		if a.MeterIndex >= maxMeter {
			return status.Errorf(codes.OutOfRange, "port: meter index %d is out of range", a.MeterIndex)
		}
	case ContextAction:
		if a.Cell >= maxCell {
			return status.Errorf(codes.OutOfRange, "context: cell %d is out of range", a.Cell)
		}
	case ForwardAction:
		if a.Cell >= maxCell || a.LocalCell >= maxCell {
			return status.Errorf(codes.OutOfRange, "forward: cell %d or local cell %d is out of range", a.Cell, a.LocalCell)
		}
	case DropAction:
		if int64(a.Reason) >= counterSizes[CounterDrops] {
			return status.Errorf(codes.OutOfRange, "drop: reason %d is out of range", a.Reason)
		}
	}
	return nil
}

// writeTable applies one update of a table entry.
func (s *state) writeTable(t *txn, typ p4.Update_Type, te *p4.TableEntry) error {
	if te.GetIsDefaultAction() {
		return status.Error(codes.PermissionDenied, "the default actions are const")
	}
	if te.GetPriority() != 0 {
		return status.Error(codes.InvalidArgument, "the tables have no priority")
	}
	var a Action
	if typ != p4.Update_DELETE {
		pa := te.GetAction().GetAction()
		if pa == nil {
			return status.Error(codes.InvalidArgument, "the entry has no action")
		}
		var err error
		if a, err = decodeAction(pa); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if !allows(te.GetTableId(), a.ActionID()) {
			return status.Errorf(codes.InvalidArgument, "table %d cannot have action %d", te.GetTableId(), a.ActionID())
		}
		if err := checkAction(a); err != nil {
			return err
		}
	}
	md := bytes.Clone(te.GetMetadata())
	switch te.GetTableId() {
	case TablePorts:
		k, err := decodePortsKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		return writeMap(t, s.ports, k.Port, typ, &entry[PortsKey]{key: k, action: a, md: md}, nil)
	case TableClassify:
		k, err := decodeClassifyKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		e := &entry[ClassifyKey]{key: k, action: a, md: md}
		return writeMap(t, s.classify, k, typ, e, func(old *entry[ClassifyKey]) {
			if n := vpcName(a); n != "" {
				e.vpc = s.ref(t, n)
			}
			if old != nil {
				if n := vpcName(old.action); n != "" {
					s.unref(t, n)
				}
			}
		})
	case TableSource:
		k, err := decodeSourceKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		sk, p := setKey{k.Port, k.Session, k.Tag}, wide(k.Src)
		l := s.source[sk]
		if err := checkLPM(l, p, typ); err != nil {
			return err
		}
		if l == nil {
			l = newLPM[*entry[SourceKey]]()
			set(t, s.source, sk, l)
		}
		if typ == p4.Update_DELETE {
			l.remove(t, p)
			if len(l.m) == 0 {
				del(t, s.source, sk)
			}
			return nil
		}
		l.put(t, p, &entry[SourceKey]{key: k, action: a, md: md})
		return nil
	case TableRoute:
		k, err := decodeRouteKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		var l *lpm[*entry[RouteKey]]
		if r := s.names[k.VPC]; r != nil {
			l = s.route[r.num]
		}
		p := wide(k.Dst)
		if err := checkLPM(l, p, typ); err != nil {
			return err
		}
		switch typ {
		case p4.Update_INSERT:
			num := s.ref(t, k.VPC)
			if l == nil {
				l = newLPM[*entry[RouteKey]]()
				set(t, s.route, num, l)
			}
			l.put(t, p, &entry[RouteKey]{key: k, action: a, md: md, vpc: num})
		case p4.Update_MODIFY:
			l.put(t, p, &entry[RouteKey]{key: k, action: a, md: md, vpc: l.m[p].vpc})
		case p4.Update_DELETE:
			num := l.m[p].vpc
			l.remove(t, p)
			if len(l.m) == 0 {
				del(t, s.route, num)
			}
			s.unref(t, k.VPC)
		}
		return nil
	}
	return status.Errorf(codes.NotFound, "unknown table %d", te.GetTableId())
}

func allows(table, action uint32) bool {
	switch table {
	case TablePorts:
		return portsAllows(action)
	case TableClassify:
		return classifyAllows(action)
	case TableSource:
		return sourceAllows(action)
	case TableRoute:
		return routeAllows(action)
	}
	return false
}

// writeMap applies an INSERT, MODIFY or DELETE of e at k. Before the change, changed gets the old
// entry (nil for INSERT).
func writeMap[K comparable, E any](t *txn, m map[K]*E, k K, typ p4.Update_Type, e *E, changed func(old *E)) error {
	old, had := m[k]
	switch typ {
	case p4.Update_INSERT:
		if had {
			return status.Error(codes.AlreadyExists, "an entry with this key exists")
		}
		if changed != nil {
			changed(nil)
		}
		set(t, m, k, e)
	case p4.Update_MODIFY:
		if !had {
			return status.Error(codes.NotFound, "no entry with this key")
		}
		if changed != nil {
			changed(old)
		}
		set(t, m, k, e)
	case p4.Update_DELETE:
		if !had {
			return status.Error(codes.NotFound, "no entry with this key")
		}
		if changed != nil {
			changed(old)
		}
		del(t, m, k)
	default:
		return status.Error(codes.InvalidArgument, "the update has no type")
	}
	return nil
}

// checkLPM checks an update of the prefix p in l, which can be nil.
func checkLPM[V any](l *lpm[V], p netip.Prefix, typ p4.Update_Type) error {
	had := false
	if l != nil {
		_, had = l.m[p]
	}
	switch {
	case typ == p4.Update_INSERT && had:
		return status.Error(codes.AlreadyExists, "an entry with this key exists")
	case (typ == p4.Update_MODIFY || typ == p4.Update_DELETE) && !had:
		return status.Error(codes.NotFound, "no entry with this key")
	case typ < p4.Update_INSERT || typ > p4.Update_DELETE:
		return status.Error(codes.InvalidArgument, "the update has no type")
	}
	return nil
}
