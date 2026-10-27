// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"maps"
	"net/netip"
	"slices"

	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Index limits of the action parameters: a cell c uses the counter indices 2c and 2c+1, and port
// meter i uses lane meters 4i to 4i+3 and the port_drops indices (i << 5) | reason.
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

// state is one copy of the tables and the keys. The packets read cur, the copy of the last Write,
// and never change its maps. A Write makes the next copy in a change.
type state struct {
	ports    map[uint64]*entry[PortsKey]
	classify map[ClassifyKey]*entry[ClassifyKey]
	source   map[setKey]*lpm[*entry[SourceKey]]
	route    map[uint32]*lpm[*entry[RouteKey]]
	names    map[string]nameRef
	free     []uint32
	nextName uint32
	rx       map[uint32]*rxSA
	tx       map[portSession]*txLanes
	meters   map[meterKey]*bucket
}

func newState() *state {
	return &state{
		ports:    map[uint64]*entry[PortsKey]{},
		classify: map[ClassifyKey]*entry[ClassifyKey]{},
		source:   map[setKey]*lpm[*entry[SourceKey]]{},
		route:    map[uint32]*lpm[*entry[RouteKey]]{},
		names:    map[string]nameRef{},
		rx:       map[uint32]*rxSA{},
		tx:       map[portSession]*txLanes{},
		meters:   map[meterKey]*bucket{},
	}
}

// change is one Write: the next copy of the tables and the keys, and the counter values to set at
// the swap. The copy shares each map of cur until the batch changes it, and then has its own copy
// of that map. For source, route and tx it copies only the changed LPM or lanes, and the map of
// them. The objects that the packets change (replay windows, sequence numbers, meter buckets) stay
// shared until the batch replaces them.
type change struct {
	st *state

	// The maps of st that this change copied.
	ports, classify, source, route, names, free, rx, tx, meters bool

	sources map[setKey]bool      // The source LPMs that it copied.
	routes  map[uint32]bool      // The route LPMs that it copied.
	lanes   map[portSession]bool // The TX lanes that it copied.

	counters []counterValue
}

// counterValue is a counter MODIFY. The swap sets it with the write lock held.
type counterValue struct {
	c              *counter
	packets, bytes uint64
}

// newChange returns a change with its copy in st, which no part reads.
func newChange(cur, st *state) *change {
	*st = *cur
	return &change{st: st}
}

// own returns *m to change. At the first change it copies *m.
func own[K comparable, V any](m *map[K]V, copied *bool) map[K]V {
	if !*copied {
		*m = maps.Clone(*m)
		*copied = true
	}
	return *m
}

// ownLPM returns the LPM of k in *m to change. At the first change it copies the LPM, or makes a
// new one, and copies *m.
func ownLPM[K comparable, V any](m *map[K]*lpm[V], copied *bool, lpms *map[K]bool, k K) *lpm[V] {
	l := (*m)[k]
	if l != nil && (*lpms)[k] {
		return l
	}
	if l == nil {
		l = newLPM[V]()
	} else {
		l = &lpm[V]{m: maps.Clone(l.m), lens: l.lens}
	}
	own(m, copied)[k] = l
	if *lpms == nil {
		*lpms = map[K]bool{}
	}
	(*lpms)[k] = true
	return l
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

func (l *lpm[V]) put(p netip.Prefix, v V) {
	if _, had := l.m[p]; !had {
		l.lens[p.Bits()]++
	}
	l.m[p] = v
}

func (l *lpm[V]) remove(p netip.Prefix) {
	if _, had := l.m[p]; had {
		l.lens[p.Bits()]--
		delete(l.m, p)
	}
}

// ref gives the number of a VPC name and counts one more entry that uses it.
func (c *change) ref(name string) uint32 {
	st := c.st
	r, ok := st.names[name]
	if !ok {
		if n := len(st.free); n > 0 {
			// A shorter slice does not write the array that cur shares.
			r.num = st.free[n-1]
			st.free = st.free[:n-1]
		} else {
			st.nextName++
			r.num = st.nextName
		}
	}
	r.refs++
	own(&st.names, &c.names)[name] = r
	return r.num
}

// unref counts one less entry that uses a VPC name, and frees its number after the last one.
func (c *change) unref(name string) {
	st := c.st
	r, ok := st.names[name]
	if !ok {
		return
	}
	r.refs--
	if r.refs > 0 {
		own(&st.names, &c.names)[name] = r
		return
	}
	delete(own(&st.names, &c.names), name)
	if !c.free {
		st.free = slices.Clone(st.free)
		c.free = true
	}
	st.free = append(st.free, r.num)
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

// writeTable applies one update of a table entry to the copy.
func (c *change) writeTable(typ p4.Update_Type, te *p4.TableEntry) error {
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
	st := c.st
	switch te.GetTableId() {
	case TablePorts:
		k, err := decodePortsKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		return writeMap(&st.ports, &c.ports, k.Port, typ, &entry[PortsKey]{key: k, action: a, md: md}, nil)
	case TableClassify:
		k, err := decodeClassifyKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		e := &entry[ClassifyKey]{key: k, action: a, md: md}
		return writeMap(&st.classify, &c.classify, k, typ, e, func(old *entry[ClassifyKey]) {
			n := vpcName(a)
			if old != nil && vpcName(old.action) == n {
				e.vpc = old.vpc // The same VPC: its count does not change.
				return
			}
			if n != "" {
				e.vpc = c.ref(n)
			}
			if old != nil {
				if n := vpcName(old.action); n != "" {
					c.unref(n)
				}
			}
		})
	case TableSource:
		k, err := decodeSourceKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		sk, p := setKey{k.Port, k.Session, k.Tag}, wide(k.Src)
		if err := checkLPM(st.source[sk], p, typ); err != nil {
			return err
		}
		l := ownLPM(&st.source, &c.source, &c.sources, sk)
		if typ == p4.Update_DELETE {
			l.remove(p)
			if len(l.m) == 0 {
				delete(st.source, sk)
			}
			return nil
		}
		l.put(p, &entry[SourceKey]{key: k, action: a, md: md})
		return nil
	case TableRoute:
		k, err := decodeRouteKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		var l *lpm[*entry[RouteKey]]
		if r, ok := st.names[k.VPC]; ok {
			l = st.route[r.num]
		}
		p := wide(k.Dst)
		if err := checkLPM(l, p, typ); err != nil {
			return err
		}
		switch typ {
		case p4.Update_INSERT:
			num := c.ref(k.VPC)
			ownLPM(&st.route, &c.route, &c.routes, num).put(p, &entry[RouteKey]{key: k, action: a, md: md, vpc: num})
		case p4.Update_MODIFY:
			num := l.m[p].vpc
			ownLPM(&st.route, &c.route, &c.routes, num).put(p, &entry[RouteKey]{key: k, action: a, md: md, vpc: num})
		case p4.Update_DELETE:
			num := l.m[p].vpc
			l = ownLPM(&st.route, &c.route, &c.routes, num)
			l.remove(p)
			if len(l.m) == 0 {
				delete(st.route, num)
			}
			c.unref(k.VPC)
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

// writeMap applies an INSERT, MODIFY or DELETE of e at k in *m, which it copies at the first change
// (own). Before the change, changed gets the old entry (nil for INSERT).
func writeMap[K comparable, E any](m *map[K]*E, copied *bool, k K, typ p4.Update_Type, e *E, changed func(old *E)) error {
	old, had := (*m)[k]
	if err := checkUpdate(had, typ); err != nil {
		return err
	}
	if changed != nil {
		changed(old)
	}
	if typ == p4.Update_DELETE {
		delete(own(m, copied), k)
	} else {
		own(m, copied)[k] = e
	}
	return nil
}

// checkLPM checks an update of the prefix p in l, which can be nil.
func checkLPM[V any](l *lpm[V], p netip.Prefix, typ p4.Update_Type) error {
	had := false
	if l != nil {
		_, had = l.m[p]
	}
	return checkUpdate(had, typ)
}

// checkUpdate checks an update of type typ of a key that is in the table when had is true.
func checkUpdate(had bool, typ p4.Update_Type) error {
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
