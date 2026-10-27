// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	"bytes"
	"maps"
	"net/netip"
	"slices"

	"github.com/gaissmai/bart"
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

// entry is one table entry. vpc is the number of the VPC name of a classify action.
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
// and never change its maps. A Write makes the next copy in a change. source and route are bart
// multibit tries, with the IPv4 prefixes in the IPv4 trie.
type state struct {
	ports    map[uint64]*entry[PortsKey]
	classify map[ClassifyKey]*entry[ClassifyKey]
	source   map[setKey]*bart.Table[*entry[SourceKey]]
	route    map[uint32]*bart.Table[*entry[RouteKey]]
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
		source:   map[setKey]*bart.Table[*entry[SourceKey]]{},
		route:    map[uint32]*bart.Table[*entry[RouteKey]]{},
		names:    map[string]nameRef{},
		rx:       map[uint32]*rxSA{},
		tx:       map[portSession]*txLanes{},
		meters:   map[meterKey]*bucket{},
	}
}

// change is one Write: the next copy of the tables and the keys, and the counter values to set at
// the swap. The copy shares each map of cur until the batch changes it, and then has its own copy
// of that map. A source or route trie changes with the path-copy calls (trieChange), and for tx it
// copies only the changed lanes. The objects that the packets change (replay windows, sequence
// numbers, meter buckets) stay shared until the batch replaces them.
type change struct {
	st *state

	// The maps of st that this change copied.
	ports, classify, source, route, names, free, rx, tx, meters bool

	sources map[setKey]*trieChange[*entry[SourceKey]] // The source tries that it changes.
	routes  map[uint32]*trieChange[*entry[RouteKey]]  // The route tries that it changes.
	lanes   map[portSession]bool                      // The TX lanes that it copied.

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

// lookup returns the value of the longest prefix of a in t. An IPv4-mapped address tries the IPv4
// prefixes first, and then the IPv6 prefixes that hold all IPv4-mapped addresses, such as ::/0.
func lookup[V any](t *bart.Table[V], a netip.Addr) (V, bool) {
	if a.Is4In6() {
		if v, ok := t.Lookup(a.Unmap()); ok {
			return v, true
		}
	}
	return t.Lookup(a)
}

// trieChange is the change of one source or route trie in a Write. A DELETE removes its prefix
// from old with the path-copy call. The INSERTs and MODIFYs go into add, a new trie that no part
// reads, and at the end of the Write one path-copy call adds them to old, so they copy each changed
// node once. The readers keep the old trie.
type trieChange[V any] struct {
	old *bart.Table[V] // The trie of cur without the deleted prefixes, or nil.
	add *bart.Table[V]
}

// changeTrie returns the change of the trie of k in m. It makes it at the first update.
func changeTrie[K comparable, V any](tcs *map[K]*trieChange[V], m map[K]*bart.Table[V], k K) *trieChange[V] {
	tc := (*tcs)[k]
	if tc == nil {
		if *tcs == nil {
			*tcs = map[K]*trieChange[V]{}
		}
		tc = &trieChange[V]{old: m[k], add: new(bart.Table[V])}
		(*tcs)[k] = tc
	}
	return tc
}

// has tells if the prefix p is in the trie after the updates so far.
func (tc *trieChange[V]) has(p netip.Prefix) bool {
	if _, ok := tc.add.Get(p); ok || tc.old == nil {
		return ok
	}
	_, ok := tc.old.Get(p)
	return ok
}

// delete removes the prefix p from add, and from old with the path-copy call.
func (tc *trieChange[V]) delete(p netip.Prefix) {
	tc.add.Delete(p)
	if tc.old != nil {
		tc.old = tc.old.DeletePersist(p)
	}
}

// commitTries puts the changed tries in *m (own), and removes the empty ones.
func commitTries[K comparable, V any](m *map[K]*bart.Table[V], copied *bool, tcs map[K]*trieChange[V]) {
	for k, tc := range tcs {
		t := tc.old
		switch {
		case t == nil || t.Size() == 0:
			t = tc.add // No part reads add, so it becomes the trie.
		case tc.add.Size() == 1: // For one prefix, InsertPersist is faster than UnionPersist.
			for p, v := range tc.add.All() {
				t = t.InsertPersist(p, v)
			}
		case tc.add.Size() > 0:
			t = t.UnionPersist(tc.add)
		}
		cur, ok := (*m)[k]
		switch {
		case t.Size() == 0:
			if ok {
				delete(own(m, copied), k)
			}
		case t != cur:
			own(m, copied)[k] = t
		}
	}
}

// commit puts the changed source and route tries in the copy. A Write calls it after its last
// update.
func (c *change) commit() {
	commitTries(&c.st.source, &c.source, c.sources)
	commitTries(&c.st.route, &c.route, c.routes)
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
		tc := changeTrie(&c.sources, st.source, setKey{k.Port, k.Session, k.Tag})
		if err := checkUpdate(tc.has(k.Src), typ); err != nil {
			return err
		}
		if typ == p4.Update_DELETE {
			tc.delete(k.Src)
		} else {
			tc.add.Insert(k.Src, &entry[SourceKey]{key: k, action: a, md: md})
		}
		return nil
	case TableRoute:
		k, err := decodeRouteKey(te.GetMatch())
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		var tc *trieChange[*entry[RouteKey]]
		had := false
		if r, ok := st.names[k.VPC]; ok {
			tc = changeTrie(&c.routes, st.route, r.num)
			had = tc.has(k.Dst)
		}
		if err := checkUpdate(had, typ); err != nil {
			return err
		}
		switch typ {
		case p4.Update_INSERT:
			tc = changeTrie(&c.routes, st.route, c.ref(k.VPC))
			fallthrough
		case p4.Update_MODIFY:
			tc.add.Insert(k.Dst, &entry[RouteKey]{key: k, action: a, md: md})
		case p4.Update_DELETE:
			tc.delete(k.Dst)
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
