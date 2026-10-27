// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"math/big"
	"slices"
)

func errAt(file string, n node, format string, args ...any) error {
	return fmt.Errorf("%s:%d: "+format, append([]any{file, n.Line()}, args...)...)
}

// The v1model names that the subset uses.
var (
	counterUnits = map[string]bool{"packets": true, "bytes": true, "packets_and_bytes": true}
	meterUnits   = map[string]bool{"packets": true, "bytes": true}
	headerOps    = []string{"isValid", "setValid", "setInvalid"}
)

const pspSa = "PspSa"

// check finds the constructs that the parser reads but the subset does not have: calls of
// other externs and methods, other instances, and names that p4gen cannot find.
func check(file string, prog *program) error {
	for _, e := range prog.externs {
		if e.name != pspSa {
			return errAt(file, e, "extern %s is not in the subset; only extern %s is", e.name, pspSa)
		}
	}
	pk := prog.main
	if pk.typ != "V1Switch" || pk.name != "main" || len(pk.args) != 6 {
		return errAt(file, pk, "only V1Switch(parser, 5 controls) main is in the subset")
	}
	if prog.parser(pk.args[0]) == nil {
		return errAt(file, pk, "%s is not a parser", pk.args[0])
	}
	for _, a := range pk.args[1:] {
		if prog.control(a) == nil {
			return errAt(file, pk, "%s is not a control", a)
		}
	}
	for _, d := range prog.parsers {
		if err := checkParser(file, prog, d); err != nil {
			return err
		}
	}
	for _, c := range prog.controls {
		if err := checkControl(file, prog, c); err != nil {
			return err
		}
	}
	return nil
}

func checkParser(file string, prog *program, d *parserDecl) error {
	states := map[string]bool{"accept": true, "reject": true}
	for _, s := range d.states {
		states[s.name] = true
	}
	if !states["start"] {
		return errAt(file, d, "parser %s has no start state", d.name)
	}
	sc := &scope{file: file, prog: prog, params: d.params}
	for _, s := range d.states {
		for _, st := range s.stmts {
			if err := sc.calls(st); err != nil {
				return err
			}
		}
		t := s.next
		targets := []string{t.to}
		if t.sel != nil {
			if err := sc.calls(t.sel); err != nil {
				return err
			}
			if _, isConst := prog.constValue(t.sel); isConst {
				return errAt(file, t, "a select of a constant is not in the subset")
			}
			targets = targets[:0]
			for _, c := range t.cases {
				if c.val != nil {
					if _, ok := prog.constValue(c.val); !ok {
						return errAt(file, c, "a select case must be a constant")
					}
				}
				targets = append(targets, c.to)
			}
		}
		for _, to := range targets {
			if !states[to] {
				return errAt(file, t, "state %s is not in parser %s", to, d.name)
			}
		}
	}
	return nil
}

func checkControl(file string, prog *program, c *controlDecl) error {
	for _, in := range c.instances {
		units := map[string]map[string]bool{"counter": counterUnits, "meter": meterUnits}[in.typ]
		switch {
		case units != nil:
			if len(in.args) != 2 {
				return errAt(file, in, "%s %s needs a size and a type", in.typ, in.name)
			}
			p, _ := path(in.args[1])
			kind := map[string]string{"counter": "CounterType.", "meter": "MeterType."}[in.typ]
			if len(p) <= len(kind) || p[:len(kind)] != kind || !units[p[len(kind):]] {
				return errAt(file, in, "%s type %s is not in the subset", in.typ, p)
			}
		case in.typ == pspSa && prog.extern(pspSa) != nil:
			if len(in.args) != 1 {
				return errAt(file, in, "%s %s needs a size", in.typ, in.name)
			}
		default:
			return errAt(file, in, "an instance of %s is not in the subset", in.typ)
		}
		if err := checkSize(file, prog, in.args[0], in.name); err != nil {
			return err
		}
	}
	sc := &scope{file: file, prog: prog, ctl: c, params: c.params}
	for _, t := range c.tables {
		for _, a := range t.actions {
			if a.name != "NoAction" && c.action(a.name) == nil {
				return errAt(file, a, "action %s is not in control %s", a.name, c.name)
			}
		}
		if t.dflt != nil {
			name := t.dflt.fun.(*ident).name
			if !slices.ContainsFunc(t.actions, func(a *ident) bool { return a.name == name }) {
				return errAt(file, t.dflt, "the default action %s is not in the actions of table %s", name, t.name)
			}
		}
		if t.size != nil {
			if err := checkSize(file, prog, t.size, "table "+t.name); err != nil {
				return err
			}
		}
	}
	for _, a := range c.actions {
		if err := sc.calls(a.body); err != nil {
			return err
		}
		if err := constIf(file, prog, a.body); err != nil {
			return err
		}
	}
	if err := sc.calls(c.apply); err != nil {
		return err
	}
	return constIf(file, prog, c.apply)
}

// checkSize fails if the size n is not a constant.
func checkSize(file string, prog *program, n node, name string) error {
	if _, ok := prog.constUint(n); !ok {
		return errAt(file, n, "the size of %s must be a constant", name)
	}
	return nil
}

// constIf fails on an if with a constant condition. p4c removes the branch that cannot run
// and the tables that only that branch applies; p4gen does not do that work.
func constIf(file string, prog *program, n node) error {
	var err error
	inspect(n, func(x node) bool {
		if s, ok := x.(*ifStmt); ok && err == nil {
			if _, isConst := prog.constValue(s.cond); isConst {
				err = errAt(file, s, "an if with a constant condition is not in the subset")
			}
		}
		return err == nil
	})
	return err
}

// scope is a control or a parser, where check finds the calls.
type scope struct {
	file   string
	prog   *program
	ctl    *controlDecl // nil in a parser.
	params []*param
}

// calls checks each call in n against the subset.
func (s *scope) calls(n node) error {
	for _, c := range calls(n) {
		if err := s.call(c); err != nil {
			return err
		}
	}
	return nil
}

func (s *scope) call(c *call) error {
	if id, ok := c.fun.(*ident); ok {
		if s.ctl != nil && (s.ctl.action(id.name) != nil || id.name == "mark_to_drop") && len(c.typeArgs) == 0 {
			return nil
		}
		return errAt(s.file, c, "a call of %s is not in the subset here", id.name)
	}
	recv, name, named := c.method()
	var allowed []string
	typeArgs := false
	switch {
	case !named:
		allowed = headerOps
	case s.ctl != nil && s.ctl.table(recv) != nil:
		allowed = []string{"apply"}
	case s.ctl != nil && s.ctl.instance(recv) != nil:
		in := s.ctl.instance(recv)
		switch in.typ {
		case "counter":
			allowed = []string{"count"}
		case "meter":
			allowed, typeArgs = []string{"execute_meter"}, true
		case pspSa:
			for _, m := range s.prog.extern(pspSa).methods {
				allowed = append(allowed, m.name)
			}
		}
	default:
		switch t := s.paramType(recv); {
		case s.prog.structType(t) != nil && s.prog.structType(t).header:
			allowed = headerOps
		case t == "packet_in":
			allowed, typeArgs = []string{"extract", "lookahead"}, name == "lookahead"
		case t == "packet_out":
			allowed = []string{"emit"}
		}
	}
	if !slices.Contains(allowed, name) {
		return errAt(s.file, c, "method %s is not in the subset here", name)
	}
	if len(c.typeArgs) > 0 && !typeArgs {
		return errAt(s.file, c, "type arguments of %s are not in the subset", name)
	}
	return nil
}

func (s *scope) paramType(name string) string {
	for _, p := range s.params {
		if p.name == name {
			return p.typ.name
		}
	}
	return ""
}

func (prog *program) parser(name string) *parserDecl {
	for _, d := range prog.parsers {
		if d.name == name {
			return d
		}
	}
	return nil
}

func (prog *program) control(name string) *controlDecl {
	for _, c := range prog.controls {
		if c.name == name {
			return c
		}
	}
	return nil
}

func (prog *program) extern(name string) *externType {
	for _, e := range prog.externs {
		if e.name == name {
			return e
		}
	}
	return nil
}

func (prog *program) structType(name string) *structType {
	for _, s := range prog.structs {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (prog *program) newType(name string) *newType {
	for _, t := range prog.newTypes {
		if t.name == name {
			return t
		}
	}
	return nil
}

func (prog *program) constDecl(name string) *constDecl {
	for _, c := range prog.consts {
		if c.name == name {
			return c
		}
	}
	return nil
}

func (c *controlDecl) action(name string) *actionDecl {
	for _, a := range c.actions {
		if a.name == name {
			return a
		}
	}
	return nil
}

func (c *controlDecl) table(name string) *tableDecl {
	for _, t := range c.tables {
		if t.name == name {
			return t
		}
	}
	return nil
}

func (c *controlDecl) instance(name string) *instance {
	for _, in := range c.instances {
		if in.name == name {
			return in
		}
	}
	return nil
}

// mainControls returns the controls of the package in V1Switch order.
func (prog *program) mainControls() []*controlDecl {
	var cs []*controlDecl
	for _, a := range prog.main.args[1:] {
		cs = append(cs, prog.control(a))
	}
	return cs
}

// constValue evaluates n if it has only literals, constants, casts and operators: a value of
// bit<W> wraps at W bits, an integer with no width does not wrap.
func (prog *program) constValue(n node) (*big.Int, bool) {
	v, _, ok := prog.eval(n, map[string]bool{})
	return v, ok
}

// constUint is constValue for a size, which must fit in a uint64.
func (prog *program) constUint(n node) (uint64, bool) {
	v, ok := prog.constValue(n)
	if !ok || v.Sign() < 0 || !v.IsUint64() {
		return 0, false
	}
	return v.Uint64(), true
}

// eval returns the value of n and its width: 0 for an integer with no width, 1 for a bool.
// visiting has the constants that n is in, to find a constant that refers to itself.
func (prog *program) eval(n node, visiting map[string]bool) (*big.Int, int, bool) {
	switch n := n.(type) {
	case *intLit:
		return n.val, n.width, true
	case *boolLit:
		return b2i(n.val), 1, true
	case *ident:
		c := prog.constDecl(n.name)
		if c == nil || visiting[c.name] {
			return nil, 0, false
		}
		visiting[c.name] = true
		defer delete(visiting, c.name)
		v, _, ok := prog.eval(c.val, visiting)
		if !ok {
			return nil, 0, false
		}
		return castTo(c.typ, v), typeWidth(c.typ), true
	case *cast:
		v, _, ok := prog.eval(n.x, visiting)
		if !ok {
			return nil, 0, false
		}
		return castTo(n.to, v), typeWidth(n.to), true
	case *cond:
		c, _, ok := prog.eval(n.c, visiting)
		if !ok {
			return nil, 0, false
		}
		if c.Sign() != 0 {
			return prog.eval(n.t, visiting)
		}
		return prog.eval(n.f, visiting)
	case *unary:
		x, w, ok := prog.eval(n.x, visiting)
		switch {
		case !ok:
			return nil, 0, false
		case n.op == "!":
			return b2i(x.Sign() == 0), 1, true
		case n.op == "-":
			return wrap(new(big.Int).Neg(x), w), w, true
		case w > 0 && n.op == "~":
			return wrap(new(big.Int).Not(x), w), w, true
		}
	case *binary:
		x, wx, okx := prog.eval(n.x, visiting)
		y, wy, oky := prog.eval(n.y, visiting)
		if okx && oky {
			return binaryValue(n.op, x, y, wx, wy)
		}
	}
	return nil, 0, false
}

func binaryValue(op string, x, y *big.Int, wx, wy int) (*big.Int, int, bool) {
	w := max(wx, wy)
	r := new(big.Int)
	switch op {
	case "==", "!=", "<", ">", "<=", ">=":
		c := x.Cmp(y)
		return b2i(map[string]bool{"==": c == 0, "!=": c != 0, "<": c < 0, ">": c > 0, "<=": c <= 0, ">=": c >= 0}[op]), 1, true
	case "&&":
		return b2i(x.Sign() != 0 && y.Sign() != 0), 1, true
	case "||":
		return b2i(x.Sign() != 0 || y.Sign() != 0), 1, true
	case "<<", ">>":
		// The width is the width of the left side.
		if y.Sign() < 0 || !y.IsInt64() || y.Int64() > 1<<16 {
			return nil, 0, false
		}
		if op == "<<" {
			return wrap(r.Lsh(x, uint(y.Int64())), wx), wx, true
		}
		return r.Rsh(x, uint(y.Int64())), wx, true
	case "+":
		r.Add(x, y)
	case "-":
		r.Sub(x, y)
	case "*":
		r.Mul(x, y)
	case "/", "%":
		if y.Sign() <= 0 || x.Sign() < 0 {
			return nil, 0, false
		}
		if op == "/" {
			r.Quo(x, y)
		} else {
			r.Rem(x, y)
		}
	case "&":
		r.And(x, y)
	case "|":
		r.Or(x, y)
	case "^":
		r.Xor(x, y)
	default:
		return nil, 0, false
	}
	return wrap(r, w), w, true
}

// wrap gives v modulo 2^w, as a bit<w> value; w 0 is no width.
func wrap(v *big.Int, w int) *big.Int {
	if w == 0 {
		return v
	}
	return new(big.Int).Mod(v, new(big.Int).Lsh(big.NewInt(1), uint(w)))
}

// typeWidth is the width of a constant of type t: 0 for a declared type.
func typeWidth(t *typeRef) int {
	switch t.name {
	case "bit":
		return t.width
	case "bool":
		return 1
	}
	return 0
}

func castTo(t *typeRef, v *big.Int) *big.Int {
	switch t.name {
	case "bit":
		return wrap(v, t.width)
	case "bool":
		return b2i(v.Sign() != 0)
	}
	return v
}

func b2i(b bool) *big.Int {
	if b {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}

// pathType returns the type of a field path such as m.p.session, with params as the roots.
func (prog *program) pathType(params []*param, n node) (*typeRef, bool) {
	switch n := n.(type) {
	case *ident:
		for _, p := range params {
			if p.name == n.name {
				return p.typ, true
			}
		}
	case *member:
		t, ok := prog.pathType(params, n.x)
		if !ok {
			return nil, false
		}
		s := prog.structType(t.name)
		if s == nil {
			return nil, false
		}
		for _, f := range s.fields {
			if f.name == n.name {
				return f.typ, true
			}
		}
	}
	return nil, false
}
