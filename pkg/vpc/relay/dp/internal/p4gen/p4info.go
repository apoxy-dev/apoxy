// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"math/big"
	"slices"

	p4config "github.com/p4lang/p4runtime/go/p4/config/v1"
)

const noAction = "NoAction"

// compiled is the P4Info of a program, and the PspSa instance that P4Info does not have for
// v1model.
type compiled struct {
	info     *p4config.P4Info
	keysName string // The full name of the one PspSa instance.
	keysID   uint32
}

// controlObjects are the objects of a control that the p4c front end keeps: the tables that
// apply runs, the actions of these tables, the actions that apply calls, and all instances. It
// removes an action that only other actions call (it inlines it), and the parameters of an
// action that only apply calls.
type controlObjects struct {
	ctl       *controlDecl
	tables    []*tableDecl
	noAction  bool          // A kept table uses NoAction.
	actions   []*actionDecl // In source order; hidden actions too, as they get IDs.
	inTable   map[string]bool
	instances []*instance
}

func objects(c *controlDecl) controlObjects {
	o := controlObjects{ctl: c, instances: c.instances, inTable: map[string]bool{}}
	applied, called := map[string]bool{}, map[string]bool{}
	for _, cl := range calls(c.apply) {
		if recv, name, ok := cl.method(); ok && name == "apply" && c.table(recv) != nil {
			applied[recv] = true
		} else if id, ok := cl.fun.(*ident); ok {
			called[id.name] = true
		}
	}
	for _, t := range c.tables {
		if !applied[t.name] {
			continue
		}
		o.tables = append(o.tables, t)
		for _, a := range t.actions {
			o.inTable[a.name] = true
		}
		if t.dflt == nil {
			o.inTable[noAction] = true
		}
	}
	o.noAction = o.inTable[noAction]
	for _, a := range c.actions {
		if o.inTable[a.name] || called[a.name] {
			o.actions = append(o.actions, a)
		}
	}
	return o
}

func qualified(c *controlDecl, name string) string { return c.name + "." + name }

// compile makes the P4Info of prog as `p4test --arch v1model --p4runtime-files` writes it.
func compile(file string, prog *program) (*compiled, error) {
	var objs []controlObjects
	for _, c := range prog.mainControls() {
		objs = append(objs, objects(c))
	}
	names := map[uint32][]string{}
	add := func(prefix p4config.P4Ids_Prefix, n string) { names[uint32(prefix)] = append(names[uint32(prefix)], n) }
	var keys []string
	var keyInst []*instance
	for _, o := range objs {
		if o.noAction {
			add(p4config.P4Ids_ACTION, noAction)
		}
		for _, a := range o.actions {
			add(p4config.P4Ids_ACTION, qualified(o.ctl, a.name))
		}
		for _, t := range o.tables {
			add(p4config.P4Ids_TABLE, qualified(o.ctl, t.name))
		}
		for _, in := range o.instances {
			switch in.typ {
			case "counter":
				add(p4config.P4Ids_COUNTER, qualified(o.ctl, in.name))
			case "meter":
				add(p4config.P4Ids_METER, qualified(o.ctl, in.name))
			case pspSa:
				keys = append(keys, qualified(o.ctl, in.name))
				keyInst = append(keyInst, in)
			}
		}
	}
	for _, s := range prog.structs {
		if s.controller != "" {
			add(p4config.P4Ids_CONTROLLER_HEADER, s.name)
		}
	}
	var all []string
	for _, ns := range names {
		all = append(all, ns...)
	}
	alias := aliases(all)
	switch {
	case len(keys) == 0:
		return nil, errAt(file, prog.main, "the controls of main have no %s instance; one is necessary", pspSa)
	case len(keys) > 1:
		return nil, errAt(file, keyInst[1], "a second %s instance is not in the subset", pspSa)
	}
	names[pspSaType] = keys
	ids, err := assignIDs(names)
	if err != nil {
		return nil, err
	}
	b := &infoBuilder{file: file, prog: prog, ids: ids, alias: alias, info: &p4config.P4Info{
		PkgInfo: &p4config.PkgInfo{Arch: "v1model"},
	}}
	for _, o := range objs {
		if err := b.control(o); err != nil {
			return nil, err
		}
	}
	for _, s := range prog.structs {
		if s.controller != "" {
			if err := b.controllerHeader(s); err != nil {
				return nil, err
			}
		}
	}
	return &compiled{info: b.info, keysName: keys[0], keysID: ids[pspSaType][keys[0]]}, nil
}

type infoBuilder struct {
	file  string
	prog  *program
	ids   map[uint32]map[string]uint32
	alias map[string]string
	info  *p4config.P4Info
	seen  map[string]bool // The actions in info.
}

func (b *infoBuilder) id(prefix p4config.P4Ids_Prefix, name string) uint32 {
	return b.ids[uint32(prefix)][name]
}

func (b *infoBuilder) preamble(prefix p4config.P4Ids_Prefix, name string) *p4config.Preamble {
	return &p4config.Preamble{Id: b.id(prefix, name), Name: name, Alias: b.alias[name]}
}

func (b *infoBuilder) control(o controlObjects) error {
	c := o.ctl
	if b.seen == nil {
		b.seen = map[string]bool{}
	}
	// The p4c front end puts NoAction first in each control that uses it.
	if o.noAction && !b.seen[noAction] {
		b.seen[noAction] = true
		p := b.preamble(p4config.P4Ids_ACTION, noAction)
		p.Annotations = []string{`@noWarn("unused")`}
		b.info.Actions = append(b.info.Actions, &p4config.Action{Preamble: p})
	}
	for _, a := range o.actions {
		name := qualified(c, a.name)
		if a.hidden || b.seen[name] {
			continue
		}
		b.seen[name] = true
		act := &p4config.Action{Preamble: b.preamble(p4config.P4Ids_ACTION, name)}
		if !o.inTable[a.name] {
			b.info.Actions = append(b.info.Actions, act)
			continue
		}
		for i, prm := range a.params {
			width, typeName, err := b.width(prm.typ)
			if err != nil {
				return errAt(b.file, prm, "action %s parameter %s: %v", a.name, prm.name, err)
			}
			act.Params = append(act.Params, &p4config.Action_Param{Id: uint32(i + 1), Name: prm.name, Bitwidth: width, TypeName: typeName})
		}
		b.info.Actions = append(b.info.Actions, act)
	}
	for _, t := range o.tables {
		if err := b.table(c, t); err != nil {
			return err
		}
	}
	for _, in := range o.instances {
		size, _ := b.prog.constUint(in.args[0])
		switch in.typ {
		case "counter":
			unit, _ := path(in.args[1])
			u := map[string]p4config.CounterSpec_Unit{"CounterType.packets": p4config.CounterSpec_PACKETS, "CounterType.bytes": p4config.CounterSpec_BYTES, "CounterType.packets_and_bytes": p4config.CounterSpec_BOTH}[unit]
			b.info.Counters = append(b.info.Counters, &p4config.Counter{
				Preamble: b.preamble(p4config.P4Ids_COUNTER, qualified(c, in.name)),
				Spec:     &p4config.CounterSpec{Unit: u},
				Size:     int64(size),
			})
		case "meter":
			unit, _ := path(in.args[1])
			u := map[string]p4config.MeterSpec_Unit{"MeterType.packets": p4config.MeterSpec_PACKETS, "MeterType.bytes": p4config.MeterSpec_BYTES}[unit]
			b.info.Meters = append(b.info.Meters, &p4config.Meter{
				Preamble: b.preamble(p4config.P4Ids_METER, qualified(c, in.name)),
				Spec:     &p4config.MeterSpec{Unit: u},
				Size:     int64(size),
			})
		}
	}
	return nil
}

func (b *infoBuilder) table(c *controlDecl, t *tableDecl) error {
	name := qualified(c, t.name)
	tb := &p4config.Table{Preamble: b.preamble(p4config.P4Ids_TABLE, name), Size: 1024}
	b.typeInfo()
	for i, k := range t.keys {
		text, _ := path(k.x)
		typ, ok := b.prog.pathType(c.params, k.x)
		if !ok {
			return errAt(b.file, k, "cannot find the type of key %s", text)
		}
		width, typeName, err := b.width(typ)
		if err != nil {
			return errAt(b.file, k, "key %s: %v", text, err)
		}
		mt := p4config.MatchField_EXACT
		if k.match == "lpm" {
			mt = p4config.MatchField_LPM
		}
		tb.MatchFields = append(tb.MatchFields, &p4config.MatchField{
			Id: uint32(i + 1), Name: text, Bitwidth: width, Match: &p4config.MatchField_MatchType_{MatchType: mt}, TypeName: typeName,
		})
	}
	actionID := func(a string) uint32 {
		if a == noAction {
			return b.id(p4config.P4Ids_ACTION, noAction)
		}
		return b.id(p4config.P4Ids_ACTION, qualified(c, a))
	}
	for _, a := range t.actions {
		tb.ActionRefs = append(tb.ActionRefs, &p4config.ActionRef{Id: actionID(a.name)})
	}
	dflt := t.dflt
	if dflt == nil {
		// As the p4c front end does: NoAction is the default, and only the default if the
		// table does not list it.
		dflt = &call{pos: t.pos, fun: &ident{t.pos, noAction}}
		if !slices.ContainsFunc(t.actions, func(a *ident) bool { return a.name == noAction }) {
			tb.ActionRefs = append(tb.ActionRefs, &p4config.ActionRef{
				Id: actionID(noAction), Annotations: []string{"@defaultonly"}, Scope: p4config.ActionRef_DEFAULT_ONLY,
			})
		}
	}
	dname := dflt.fun.(*ident).name
	if t.dfltConst {
		tb.ConstDefaultActionId = actionID(dname)
	}
	da := &p4config.TableActionCall{ActionId: actionID(dname)}
	if dname != noAction {
		a := c.action(dname)
		if len(dflt.args) != len(a.params) {
			return errAt(b.file, dflt, "default action %s needs %d arguments", dname, len(a.params))
		}
		for i, arg := range dflt.args {
			x, ok := b.prog.constValue(arg)
			if !ok {
				return errAt(b.file, arg, "default action %s argument %d is not a constant", dname, i+1)
			}
			v, err := value(a.params[i].typ, x)
			if err != nil {
				return errAt(b.file, arg, "default action %s argument %d: %v", dname, i+1, err)
			}
			da.Arguments = append(da.Arguments, &p4config.TableActionCall_Argument{ParamId: uint32(i + 1), Value: v})
		}
	}
	tb.InitialDefaultAction = da
	if t.size != nil {
		if size, _ := b.prog.constUint(t.size); size != 0 {
			tb.Size = int64(size)
		}
	}
	b.info.Tables = append(b.info.Tables, tb)
	return nil
}

func (b *infoBuilder) controllerHeader(s *structType) error {
	h := &p4config.ControllerPacketMetadata{Preamble: &p4config.Preamble{
		Id:          b.id(p4config.P4Ids_CONTROLLER_HEADER, s.name),
		Name:        s.controller,
		Alias:       s.controller,
		Annotations: []string{fmt.Sprintf("@controller_header(%q)", s.controller)},
	}}
	for i, f := range s.fields {
		if f.typ.name != "bit" {
			return errAt(b.file, f, "a controller header field must be bit<N>")
		}
		b.typeInfo()
		h.Metadata = append(h.Metadata, &p4config.ControllerPacketMetadata_Metadata{Id: uint32(i + 1), Name: f.name, Bitwidth: int32(f.typ.width)})
	}
	b.info.ControllerPacketMetadata = append(b.info.ControllerPacketMetadata, h)
	return nil
}

// typeInfo returns the type info of P4Info. p4c makes it, empty if no type is translated, for
// each table, action parameter and controller header field (mutable_type_info in
// p4RuntimeSerializer.cpp), so p4gen does that too.
func (b *infoBuilder) typeInfo() *p4config.P4TypeInfo {
	if b.info.TypeInfo == nil {
		b.info.TypeInfo = &p4config.P4TypeInfo{}
	}
	return b.info.TypeInfo
}

// width returns the P4Info width of t, or the name of its translated type. Like p4c, it makes
// the type info.
func (b *infoBuilder) width(t *typeRef) (int32, *p4config.P4NamedType, error) {
	b.typeInfo()
	switch t.name {
	case "bit":
		return int32(t.width), nil, nil
	case "bool":
		return 1, nil, nil
	}
	nt := b.prog.newType(t.name)
	if nt == nil {
		return 0, nil, fmt.Errorf("type %s is not bit<N>, bool or a translated type", t.name)
	}
	ti := b.typeInfo()
	if ti.NewTypes == nil {
		ti.NewTypes = map[string]*p4config.P4NewTypeSpec{}
	}
	ti.NewTypes[nt.name] = &p4config.P4NewTypeSpec{Representation: &p4config.P4NewTypeSpec_TranslatedType{
		TranslatedType: &p4config.P4NewTypeTranslation{Uri: nt.uri, SdnType: &p4config.P4NewTypeTranslation_SdnString_{SdnString: &p4config.P4NewTypeTranslation_SdnString{}}},
	}}
	return 0, &p4config.P4NamedType{Name: nt.name}, nil
}

// value returns the bytes of v, a value of type t, as p4c writes them: big endian, padded to
// the width (control-plane/bytestrings.cpp).
func value(t *typeRef, v *big.Int) ([]byte, error) {
	width := 1
	switch t.name {
	case "bit":
		width = t.width
	case "bool":
	default:
		return nil, fmt.Errorf("a value of type %s is not in the subset", t.name)
	}
	if v.Sign() < 0 || v.BitLen() > width {
		return nil, fmt.Errorf("%v does not fit in %d bits", v, width)
	}
	return v.FillBytes(make([]byte, (width+7)/8)), nil
}
