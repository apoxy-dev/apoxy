// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"fmt"
	gotoken "go/token"
	"go/types"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

// The Go writer of the pipeline. It writes the Go types of the headers and the metadata, and two
// methods of the type part of the runtime: parse (the parser and the control up to keys.open) and
// apply (the rest of the control). The code uses these names of the hand-written runtime:
//
//   - type part, with st *state, and type packet, which has the generated pass in it.
//   - x.st.lookup<Table>(keys...) gives the entry of the keys or nil. e.<param> is the number of a
//     translated action parameter.
//   - x.countIndex(id, i, pkt) and x.executeMeter(id, i, pkt) uint8 for the counters and meters.
//   - x.step<Action>(pkt) bool for an empty @hidden action (a Go step). True is an exit.
//   - <function>(pkt, args...) for an extern function. An out argument is a pointer.
//   - The PspSa methods on *part.

// pipe writes the pipeline code of one program.
type pipe struct {
	file   string
	prog   *program
	ctl    *controlDecl // The ingress control.
	parser *parserDecl
	keys   *instance // The PspSa instance of ctl, or nil.
	sp     *splitPoint
	open   *call // The keys.open call of sp.
	hdrs   string
	meta   string
	pktIn  string // The packet_in parameter of the parser.

	b         *bytes.Buffer
	root      *env // The parameters of ctl.
	inParse   bool
	parseExit bool // parse has an exit.
	endUsed   bool
	at        map[*ifStmt]int // The start point of apply for each if on the path to the split.
	nextAt    int
	pathVars  []pathVar
	lookahead map[*call]string
	pspCalls  map[string]bool
	ctlMeta   string // The Go type of the controller header that the parser extracts.
	reserved  map[string]bool

	imports           map[string]bool // The packages that the code uses.
	usesCond, usesBit bool
}

// pathVar is a local of apply that parse sets: a field of pass.
type pathVar struct {
	p4Name, field, typ string
}

type pipeErr struct{ err error }

func (w *pipe) fail(n node, format string, args ...any) {
	panic(pipeErr{errAt(w.file, n, format, args...)})
}

func (w *pipe) p(format string, args ...any) { fmt.Fprintf(w.b, format+"\n", args...) }

// sym is a P4 name in a scope: its Go code and its P4 type.
type sym struct {
	code string
	t    *typeRef
}

type env struct {
	up   *env
	syms map[string]sym
}

func newEnv(up *env) *env { return &env{up: up, syms: map[string]sym{}} }

func (s *env) lookup(name string) (sym, bool) {
	for ; s != nil; s = s.up {
		if v, ok := s.syms[name]; ok {
			return v, true
		}
	}
	return sym{}, false
}

// ex is the Go code of an expression and its P4 type. atom tells that the code needs no
// parentheses as an operand.
type ex struct {
	code string
	t    *typeRef
	atom bool
}

func (e ex) operand() string {
	if e.atom {
		return e.code
	}
	return "(" + e.code + ")"
}

var (
	intT  = &typeRef{name: "int"}
	boolT = &typeRef{name: "bool"}
	errT  = &typeRef{name: "error"}
	voidT = &typeRef{name: "void"}
)

func bitT(width int) *typeRef { return &typeRef{name: "bit", width: width} }

// smFields are the fields of standard_metadata_t that the Go writer has.
var smFields = map[string]struct {
	goName string
	t      *typeRef
}{
	"ingress_port":  {"ingressPort", bitT(9)},
	"egress_spec":   {"egressSpec", bitT(9)},
	"packet_length": {"packetLength", bitT(32)},
	"parser_error":  {"parserError", errT},
}

// pipeline writes the Go code of the pipeline of prog: the code after the imports. It also gives
// the packages that the code uses.
func pipeline(file string, prog *program) (code []byte, imports map[string]bool, err error) {
	w := &pipe{file: file, prog: prog, at: map[*ifStmt]int{}, nextAt: 3, lookahead: map[*call]string{}, pspCalls: map[string]bool{},
		imports: map[string]bool{}}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(pipeErr)
			if !ok {
				panic(r)
			}
			err = pe.err
		}
	}()
	return w.write(), w.imports, nil
}

func (w *pipe) write() []byte {
	cs := w.prog.mainControls() // Verify, ingress, egress, compute, deparser.
	w.ctl = cs[1]
	for _, c := range []*controlDecl{cs[0], cs[2], cs[3]} {
		if len(c.apply.stmts) > 0 {
			w.fail(c.apply.stmts[0], "control %s must have an empty apply: the Go writer runs only the ingress control %s", c.name, w.ctl.name)
		}
	}
	ps := w.ctl.params
	if len(ps) != 3 || ps[2].typ.name != "standard_metadata_t" || w.prog.structType(ps[0].typ.name) == nil || w.prog.structType(ps[1].typ.name) == nil {
		w.fail(w.ctl, "the ingress control must have the parameters (headers, metadata, standard_metadata_t)")
	}
	w.hdrs, w.meta = ps[0].typ.name, ps[1].typ.name
	w.parser = w.prog.parser(w.prog.main.args[0])
	pp := w.parser.params
	if len(pp) != 4 || pp[0].typ.name != "packet_in" || pp[1].typ.name != w.hdrs || pp[2].typ.name != w.meta || pp[3].typ.name != "standard_metadata_t" {
		w.fail(w.parser, "the parser must have the parameters (packet_in, headers, metadata, standard_metadata_t) of the ingress control")
	}
	w.pktIn = pp[0].name
	for _, in := range w.ctl.instances {
		if in.typ == pspSa {
			w.keys = in
		}
	}
	sp, err := split(w.file, w.prog)
	if err != nil {
		panic(pipeErr{err})
	}
	if sp != nil {
		if sp.ctl != w.ctl {
			w.fail(sp.stmt, "the split must be in the ingress control %s", w.ctl.name)
		}
		w.sp = sp
		switch s := sp.stmt.(type) {
		case *varDecl:
			w.open = s.init.(*call)
		case *assign:
			w.open = s.rhs.(*call)
		}
	}
	w.reserve()
	w.root = newEnv(nil)
	for i, s := range []string{"pkt.h", "pkt.m", "pkt.sm"} {
		w.root.syms[ps[i].name] = sym{s, ps[i].typ}
	}

	// The methods first: the types after them need their locals and calls.
	var fns bytes.Buffer
	w.b = &fns
	w.functions()
	var out bytes.Buffer
	w.b = &out
	w.consts()
	w.types()
	w.pass()
	w.pspSa()
	out.Write(fns.Bytes())
	w.helpers()
	return out.Bytes()
}

// reserve sets the Go names that a local must not have.
func (w *pipe) reserve() {
	// v and b of the parser code are in their own blocks, with no locals of P4 there.
	w.reserved = map[string]bool{"x": true, "pkt": true, "e": true, "a": true, "binary": true, "netip": true,
		"atOpen": true, "atExit": true, "pass": true, "part": true, "packet": true, "headers": true, "meta": true,
		"standardMetadata": true}
	for _, c := range w.prog.consts {
		w.reserved[w.constName(c)] = true
	}
	for _, f := range w.prog.funcs {
		w.reserved[lowerCamel(f.name)] = true
	}
	for _, s := range w.prog.structs {
		w.reserved[w.structName(s.name)] = true
	}
}

// goName checks the Go name of a local, a parameter, a constant or an extern function.
func (w *pipe) goName(n node, name string, local bool) string {
	g := lowerCamel(strings.ToLower(name))
	if local {
		g = lowerCamel(name)
	}
	switch {
	case g == "" || gotoken.IsKeyword(g) || types.Universe.Lookup(g) != nil || strings.HasPrefix(g, "p4") || strings.HasPrefix(g, "pState"):
		w.fail(n, "the name %s has the Go name %s, which Go or the Go writer uses", name, g)
	case local && (w.reserved[g] || w.prog.constDecl(name) != nil):
		w.fail(n, "the local %s has the Go name %s, which the Go writer uses", name, g)
	}
	return g
}

func (w *pipe) constName(c *constDecl) string {
	if isReason(c) {
		return "Reason" + camel(strings.ToLower(c.name[2:]))
	}
	return lowerCamel(strings.ToLower(c.name))
}

func isReason(c *constDecl) bool {
	return strings.HasPrefix(c.name, "R_") && c.typ.name == "bit" && c.typ.width == 8
}

// lowerCamel is the Go name of a P4 name: the first part in lower case, the others as camel.
func lowerCamel(name string) string {
	var s strings.Builder
	for _, part := range strings.Split(name, "_") {
		switch {
		case part == "":
		case s.Len() == 0:
			s.WriteString(strings.ToLower(part))
		default:
			s.WriteString(camel(part))
		}
	}
	return s.String()
}

func (w *pipe) structName(name string) string {
	switch name {
	case w.hdrs:
		return "headers"
	case w.meta:
		return "meta"
	}
	return lowerFirst(camel(name))
}

func (w *pipe) fieldName(s *structType, f *structField) string {
	g := lowerCamel(f.name)
	if gotoken.IsKeyword(g) || s.header && g == "valid" {
		w.fail(f, "the field %s has the Go name %s, which Go or the Go writer uses", f.name, g)
	}
	return g
}

// base is t, or the base type of a declared type.
func (w *pipe) base(t *typeRef) *typeRef {
	if nt := w.prog.newType(t.name); nt != nil {
		return nt.base
	}
	return t
}

// goBits is the width of the Go type of bit<width>.
func goBits(width int) int {
	for _, b := range []int{8, 16, 32, 64} {
		if width <= b {
			return b
		}
	}
	return 0
}

func (w *pipe) goType(n node, t *typeRef) string {
	t = w.base(t)
	switch t.name {
	case "bit":
		switch {
		case t.width >= 1 && t.width <= 64:
			return "uint" + strconv.Itoa(goBits(t.width))
		case t.width == 128:
			w.imports["net/netip"] = true
			return "netip.Addr"
		case t.width == 144:
			w.imports["net/netip"] = true
			return "netip.AddrPort"
		}
		w.fail(n, "bit<%d> has no Go type in the Go writer", t.width)
	case "bool":
		return "bool"
	case "error":
		return "uint8"
	case "standard_metadata_t":
		return "standardMetadata"
	}
	if s := w.prog.structType(t.name); s != nil {
		return w.structName(s.name)
	}
	w.fail(n, "the type %s has no Go type in the Go writer", t.name)
	return ""
}

func typeText(t *typeRef) string {
	if t.name == "bit" {
		return fmt.Sprintf("bit<%d>", t.width)
	}
	return t.name
}

// lit is the Go text of a constant value.
func lit(v *big.Int) string {
	if v.Sign() >= 0 && v.Cmp(big.NewInt(1024)) >= 0 {
		return "0x" + v.Text(16)
	}
	return v.String()
}

func ones(width int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(width)), big.NewInt(1))
}

func (w *pipe) consts() {
	w.p("// The constants of %s that are not drop reasons.", w.file)
	w.p("const (")
	for _, c := range w.prog.consts {
		if isReason(c) {
			continue
		}
		name := w.goName(c, c.name, false)
		v, ok := w.prog.constValue(&ident{c.pos, c.name})
		t := w.base(c.typ)
		switch {
		case !ok:
			w.fail(c, "%s is not a constant", c.name)
		case t.name == "bool":
			w.p("%s bool = %t", name, v.Sign() != 0)
		case t.name == "bit" && t.width <= 64:
			w.p("%s %s = %s", name, w.goType(c, t), lit(v))
		default:
			w.fail(c, "a constant of type %s is not in the subset of the Go writer", typeText(c.typ))
		}
	}
	w.p(")")
	w.p("")
	w.p("// The errors of core.p4: the values of parser_error.")
	w.p("const (")
	for i, e := range coreErrors {
		if i == 0 {
			w.p("p4Err%s uint8 = iota", e)
		} else {
			w.p("p4Err%s", e)
		}
	}
	w.p(")")
	w.p("")
	w.p("// p4DropPort is the egress_spec of mark_to_drop.")
	w.p("const p4DropPort uint16 = 511")
	w.p("")
	if w.sp != nil {
		w.p("// The start points of apply in pass.at: after %s.open, or at the end after an exit in parse.", w.keys.name)
		w.p("// A branch of the first if that parse did not run has a start point of 3 or more.")
		w.p("const (")
		w.p("atOpen = 1")
		w.p("atExit = 2")
		w.p(")")
		w.p("")
	}
}

func (w *pipe) types() {
	for _, s := range w.prog.structs {
		name := w.structName(s.name)
		if s.header {
			w.p("// %s is the header %s. valid is its validity.", name, s.name)
		} else {
			w.p("// %s is the struct %s.", name, s.name)
		}
		w.p("type %s struct {", name)
		if s.header {
			w.p("valid bool")
		}
		for _, f := range s.fields {
			w.p("%s %s // %s", w.fieldName(s, f), w.goType(f, f.typ), typeText(f.typ))
		}
		w.p("}")
		w.p("")
	}
	w.p("// standardMetadata has the fields of standard_metadata_t that the Go writer has.")
	w.p("type standardMetadata struct {")
	w.p("ingressPort uint16 // bit<9>")
	w.p("egressSpec uint16 // bit<9>")
	w.p("packetLength uint32 // The length of the packet in.")
	w.p("parserError uint8")
	w.p("}")
	w.p("")
	// The PacketIn metadata of a controller header that the parser does not extract.
	for _, s := range w.prog.structs {
		if s.controller == "" || camel(s.controller)+"Meta" == w.ctlMeta {
			continue
		}
		meta := camel(s.controller) + "Meta"
		var fs []string
		for _, f := range s.fields {
			code := "hd." + w.fieldName(s, f)
			switch t := w.base(f.typ); {
			case w.prog.newType(f.typ.name) != nil:
				w.fail(f, "a translated field of a controller header is not in the subset of the Go writer")
			case t.name == "bit" && t.width == 1:
				code += " != 0"
			}
			fs = append(fs, camel(f.name)+": "+code)
		}
		w.p("// metadata returns the %s controller header of hd.", s.controller)
		w.p("func (hd *%s) metadata() %s {", w.structName(s.name), meta)
		w.p("return %s{%s}", meta, strings.Join(fs, ", "))
		w.p("}")
		w.p("")
	}
}

func (w *pipe) pass() {
	w.p("// pass is one packet in the pipeline: the packet, its headers and metadata, and where apply")
	w.p("// starts.")
	w.p("type pass struct {")
	w.p("h headers")
	w.p("m meta")
	w.p("sm standardMetadata")
	w.p("in []byte // The packet in.")
	w.p("off int // The bytes of in that the parser took.")
	w.p("data []byte // The packet after its parsed headers.")
	if w.ctlMeta != "" {
		w.p("ctl %s // The controller header of a PacketOut.", w.ctlMeta)
	}
	if w.sp != nil {
		w.p("at uint8 // Where apply starts: atOpen, atExit or a branch of the first if.")
		w.p("open %s // The value of %s.open.", w.goType(w.open, w.methodOf("open").ret), w.keys.name)
	}
	for _, v := range w.pathVars {
		w.p("%s %s // The local %s of apply, which parse sets.", v.field, v.typ, v.p4Name)
	}
	w.p("}")
	w.p("")
}

func (w *pipe) methodOf(name string) *method {
	for _, m := range w.prog.extern(pspSa).methods {
		if m.name == name {
			return m
		}
	}
	return nil
}

// signature is the Go parameter list and result of m, with first and last added to the parameters.
func (w *pipe) signature(m *method, first, last string) string {
	var ps []string
	if first != "" {
		ps = append(ps, first)
	}
	for _, prm := range m.params {
		ps = append(ps, w.goName(prm, prm.name, true)+" "+w.goType(prm, prm.typ))
	}
	if last != "" {
		ps = append(ps, last)
	}
	s := "(" + strings.Join(ps, ", ") + ")"
	if m.ret != nil {
		s += " " + w.goType(m, m.ret)
	}
	return s
}

func (w *pipe) pspSa() {
	if w.keys == nil {
		return
	}
	w.p("// PspSa is the extern %s of %s, with the methods that the pipeline calls. The runtime", pspSa, w.file)
	w.p("// implements it on *part.")
	w.p("type PspSa interface {")
	for _, m := range w.prog.extern(pspSa).methods {
		switch {
		case w.sp != nil && m.name == "open":
			w.p("// Open is the first half of %s.open, in parse: 0 and one open op, or a drop reason.", w.keys.name)
			w.p("Open%s", w.signature(m, "pkt *packet", "m *meta"))
			w.p("// Opened is the second half of %s.open, in apply in RX order, after the AEAD.", w.keys.name)
			w.p("Opened(pkt *packet, m *meta) %s", w.goType(m, m.ret))
		case w.pspCalls[m.name]:
			w.p("%s%s", camel(m.name), w.signature(m, "", ""))
		}
	}
	w.p("}")
	w.p("")
}

func (w *pipe) helpers() {
	if w.usesCond {
		w.p("// p4cond is the ?: operator of P4.")
		w.p("func p4cond[T any](c bool, a, b T) T {")
		w.p("if c {")
		w.p("return a")
		w.p("}")
		w.p("return b")
		w.p("}")
		w.p("")
	}
	if w.usesBit {
		w.p("// p4bit is the bit<1> value of a bool.")
		w.p("func p4bit(b bool) uint8 {")
		w.p("if b {")
		w.p("return 1")
		w.p("}")
		w.p("return 0")
		w.p("}")
		w.p("")
	}
}

func (w *pipe) functions() {
	keys := "the split"
	if w.keys != nil {
		keys = w.keys.name + ".open"
	}
	w.p("// parse runs the parser and the control %s up to %s. It counts nothing: a branch", w.ctl.name, keys)
	w.p("// that it does not run, or an exit, only sets pkt.at, and apply runs it in RX order.")
	w.p("func (x *part) parse(pkt *packet) {")
	w.parserCode()
	if w.sp != nil {
		w.inParse = true
		w.parsePath(w.ctl.apply.stmts, newEnv(w.root), true)
		w.inParse = false
	}
	w.p("}")
	w.p("")
	w.p("// apply runs the control %s from %s on.", w.ctl.name, keys)
	w.p("func (x *part) apply(pkt *packet) {")
	if w.parseExit {
		w.p("if pkt.at == atExit {")
		w.p("return")
		w.p("}")
	}
	if w.sp != nil {
		w.resumeList(w.ctl.apply.stmts, newEnv(w.root))
	} else {
		w.stmts(w.ctl.apply.stmts, newEnv(w.root))
	}
	w.p("}")
	w.p("")
}

// The parser.

func (w *pipe) parserCode() {
	d := w.parser
	sc := newEnv(nil)
	for i, s := range []string{"pkt.h", "pkt.m", "pkt.sm"} {
		sc.syms[d.params[i+1].name] = sym{s, d.params[i+1].typ}
	}
	state := map[string]*parserState{}
	for _, s := range d.states {
		state[s.name] = s
	}
	// The states that start can reach, start first, then in source order. A label for each target.
	reached := map[string]bool{"start": true}
	targets := map[string]bool{}
	for todo := []string{"start"}; len(todo) > 0; {
		s := state[todo[0]]
		todo = todo[1:]
		if s == nil {
			continue
		}
		next := []string{s.next.to}
		if s.next.sel != nil {
			next = next[:0]
			for _, c := range s.next.cases {
				next = append(next, c.to)
			}
		}
		for _, to := range next {
			targets[to] = true
			if !reached[to] {
				reached[to] = true
				todo = append(todo, to)
			}
		}
	}
	order := []*parserState{state["start"]}
	for _, s := range d.states {
		if s.name != "start" && reached[s.name] {
			order = append(order, s)
		}
	}
	w.p("// The parser %s.", d.name)
	for _, s := range order {
		if targets[s.name] {
			w.p("pState%s:", camel(s.name))
		}
		for _, st := range s.stmts {
			w.parserStmt(st, sc)
		}
		w.transition(s.next, sc)
	}
	if w.endUsed {
		w.p("pEnd:")
	}
	w.p("pkt.data = pkt.in[pkt.off:]")
}

func (w *pipe) jump(to string) string {
	if to == "accept" || to == "reject" {
		// An explicit reject does not change parser_error.
		w.endUsed = true
		return "goto pEnd"
	}
	return "goto pState" + camel(to)
}

func (w *pipe) tooShort(n int) {
	w.endUsed = true
	w.p("if len(pkt.in)-pkt.off < %d {", n)
	w.p("pkt.sm.parserError = p4ErrPacketTooShort")
	w.p("goto pEnd")
	w.p("}")
}

func (w *pipe) parserStmt(s node, sc *env) {
	switch s := s.(type) {
	case *assign:
		w.assign(s, sc)
		return
	case *callStmt:
		recv, name, named := s.call.method()
		switch {
		case named && recv == w.pktIn && name == "extract":
			w.extract(s.call, sc)
			return
		case !named && (name == "setValid" || name == "setInvalid"):
			w.callStmt(s.call, sc)
			return
		}
	}
	w.fail(s, "this statement in a parser state is not in the subset of the Go writer")
}

func (w *pipe) extract(c *call, sc *env) {
	if len(c.args) != 1 {
		w.fail(c, "extract has one argument in the subset")
	}
	h := w.expr(c.args[0], sc)
	st := w.prog.structType(w.base(h.t).name)
	if st == nil || !st.header {
		w.fail(c, "extract needs a header")
	}
	name := w.structName(st.name)
	var fs []string
	if st.controller != "" {
		// A controller header comes from the PacketOut metadata, with no bytes.
		meta := camel(st.controller) + "Meta"
		if w.ctlMeta != "" && w.ctlMeta != meta {
			w.fail(c, "the parser extracts one controller header in the subset of the Go writer")
		}
		w.ctlMeta = meta
		for _, f := range st.fields {
			code := "pkt.ctl." + camel(f.name)
			switch t := w.base(f.typ); {
			case w.prog.newType(f.typ.name) != nil:
				w.fail(f, "a translated field of a controller header is not in the subset of the Go writer")
			case t.name == "bit" && t.width == 1:
				w.usesBit = true
				code = "p4bit(" + code + ")"
			}
			fs = append(fs, w.fieldName(st, f)+": "+code)
		}
		w.p("%s = %s{valid: true, %s}", h.code, name, strings.Join(fs, ", "))
		return
	}
	off := 0
	for _, f := range st.fields {
		t := w.base(f.typ)
		if t.name != "bit" {
			w.fail(f, "an extracted header has only bit<N> fields in the subset of the Go writer")
		}
		fs = append(fs, w.fieldName(st, f)+": "+w.fieldBits(f, off, t.width, w.goType(f, t)))
		off += t.width
	}
	if off%8 != 0 {
		w.fail(c, "header %s has %d bits, not whole bytes", st.name, off)
	}
	n := off / 8
	w.tooShort(n)
	w.p("{")
	w.p("b := pkt.in[pkt.off : pkt.off+%d]", n)
	w.p("%s = %s{valid: true, %s}", h.code, name, strings.Join(fs, ", "))
	w.p("}")
	w.p("pkt.off += %d", n)
}

// fieldBits is the code that reads bits [off, off+width) of b, in the Go type gt.
func (w *pipe) fieldBits(n node, off, width int, gt string) string {
	i, j := off/8, (off+width-1)/8
	if off%8 == 0 {
		switch width {
		case 8:
			return fmt.Sprintf("b[%d]", i)
		case 16, 32, 64:
			w.imports["encoding/binary"] = true
			return fmt.Sprintf("binary.BigEndian.Uint%d(b[%d:])", width, i)
		}
	}
	nb := j - i + 1
	if width > 64 || nb > 8 {
		w.fail(n, "a header field of %d bits at bit %d is not in the subset of the Go writer", width, off)
	}
	shift := 8*(j+1) - (off + width)
	at := "uint" + strconv.Itoa(goBits(8*nb))
	var parts []string
	for k := i; k <= j; k++ {
		s := fmt.Sprintf("b[%d]", k)
		if nb > 1 {
			s = fmt.Sprintf("%s(%s)", at, s)
			if k < j {
				s += fmt.Sprintf("<<%d", 8*(j-k))
			}
		}
		parts = append(parts, s)
	}
	code := strings.Join(parts, " | ")
	if nb > 1 {
		code = "(" + code + ")"
	}
	if shift > 0 {
		code += fmt.Sprintf(" >> %d", shift)
	}
	if off%8 != 0 {
		code += " & " + lit(ones(width))
	}
	if at != gt {
		code = gt + "(" + code + ")"
	}
	return code
}

func (w *pipe) transition(t *transition, sc *env) {
	if t.sel == nil {
		w.p("%s", w.jump(t.to))
		return
	}
	for _, c := range calls(t.sel) {
		recv, name, ok := c.method()
		if !ok || recv != w.pktIn || name != "lookahead" {
			continue
		}
		width := 0
		if len(c.typeArgs) == 1 && c.typeArgs[0].name == "bit" {
			width = c.typeArgs[0].width
		}
		if width%8 != 0 || width < 8 || width > 64 {
			w.fail(c, "lookahead of whole bytes, 64 bits or less, is in the subset of the Go writer")
		}
		w.tooShort(width / 8)
		code := "pkt.in[pkt.off]"
		switch width {
		case 8:
		case 16, 32, 64:
			w.imports["encoding/binary"] = true
			code = fmt.Sprintf("binary.BigEndian.Uint%d(pkt.in[pkt.off:])", width)
		default:
			code = w.fieldBits(c, 0, width, w.goType(c, c.typeArgs[0]))
			code = strings.ReplaceAll(code, "b[", "pkt.in[pkt.off+")
		}
		w.lookahead[c] = code
	}
	if len(t.cases) == 1 && t.cases[0].val == nil {
		w.p("%s", w.jump(t.cases[0].to))
		return
	}
	sel := w.expr(t.sel, sc)
	st := w.base(sel.t)
	w.p("switch v := %s; {", sel.code)
	dflt := false
	for i, c := range t.cases {
		switch v := c.val.(type) {
		case nil:
			if i != len(t.cases)-1 {
				w.fail(c, "the default case of a select must be the last one")
			}
			dflt = true
			w.p("default:")
		case *rangeExpr:
			lo, _ := w.prog.constValue(v.lo)
			hi, _ := w.prog.constValue(v.hi)
			var conds []string
			if lo.Sign() > 0 {
				conds = append(conds, w.caseVal(v.lo, st)+" <= v")
			}
			if st.name != "bit" || hi.Cmp(ones(st.width)) < 0 {
				conds = append(conds, "v <= "+w.caseVal(v.hi, st))
			}
			if len(conds) == 0 {
				w.fail(c, "a range that has all values is not in the subset of the Go writer: use default")
			}
			w.p("case %s:", strings.Join(conds, " && "))
		default:
			w.p("case v == %s:", w.caseVal(v, st))
		}
		w.p("%s", w.jump(c.to))
	}
	w.p("}")
	if !dflt {
		w.endUsed = true
		w.p("pkt.sm.parserError = p4ErrNoMatch")
		w.p("goto pEnd")
	}
}

func (w *pipe) caseVal(n node, t *typeRef) string {
	if id, ok := n.(*ident); ok {
		if c := w.prog.constDecl(id.name); c != nil {
			return w.constName(c)
		}
	}
	v, _ := w.prog.constValue(n)
	if t.name == "bool" {
		return strconv.FormatBool(v.Sign() != 0)
	}
	return lit(v)
}

// The control.

// onPath reports whether n has the split call.
func (w *pipe) onPath(n node) bool { return n != nil && contains(n, w.open) }

func stmtList(n node) []node {
	switch n := n.(type) {
	case nil:
		return nil
	case *block:
		return n.stmts
	}
	return []node{n}
}

// parsePath writes the parse code of ss, a statement list on the path to the split. tail tells
// that no code comes after it.
func (w *pipe) parsePath(ss []node, sc *env, tail bool) {
	for i, s := range ss {
		if !w.onPath(s) {
			if v, ok := s.(*varDecl); ok {
				// A local before the split is a field of pass, so that apply sees it.
				w.declare(sc, v, v.name)
				field := "l" + camel(v.name)
				for _, pv := range w.pathVars {
					if pv.field == field {
						w.fail(v, "two locals named %s before the split are not in the subset of the Go writer", v.name)
					}
				}
				w.pathVars = append(w.pathVars, pathVar{v.name, field, w.goType(v, v.typ)})
				sc.syms[v.name] = sym{"pkt." + field, v.typ}
				if v.init != nil {
					w.p("pkt.%s = %s", field, w.value(v.init, v.typ, sc))
				}
				continue
			}
			if w.stmt(s, sc, ss[i+1:]) {
				return
			}
			continue
		}
		switch s := s.(type) {
		case *block:
			w.parsePath(s.stmts, newEnv(sc), tail)
		case *ifStmt:
			n := w.nextAt
			w.nextAt++
			w.at[s] = n
			cond := w.expr(s.cond, sc).code
			if w.onPath(s.then) {
				w.p("if %s {", cond)
				w.parsePath(stmtList(s.then), newEnv(sc), false)
				w.p("}")
				w.p("pkt.at = %d", n)
				if !tail {
					w.p("return")
				}
			} else {
				w.p("if %s {", cond)
				w.p("pkt.at = %d", n)
				w.p("return")
				w.p("}")
				w.parsePath(stmtList(s.els), newEnv(sc), tail)
			}
		default:
			m := w.methodOf("open")
			args := []string{"pkt"}
			for j, a := range w.open.args {
				args = append(args, w.value(a, m.params[j].typ, sc))
			}
			w.p("pkt.open = x.Open(%s, &pkt.m)", strings.Join(args, ", "))
			w.p("pkt.at = atOpen")
			if !tail {
				w.p("return")
			}
		}
		return
	}
}

// resumeList writes the apply code of ss, a statement list on the path to the split: the locals
// that parse set, the statement on the path, and the statements after it. It reports whether the
// code exits.
func (w *pipe) resumeList(ss []node, sc *env) bool {
	k := slices.IndexFunc(ss, w.onPath)
	for _, s := range ss[:k] {
		v, ok := s.(*varDecl)
		if !ok {
			continue
		}
		name := w.declare(sc, v, v.name)
		sc.syms[v.name] = sym{name, v.typ}
		if !refers(ss[k:], v.name) {
			continue
		}
		w.p("var %s %s = pkt.l%s", name, w.goType(v, v.typ), camel(v.name))
		if !reads(ss[k:], v.name) {
			w.p("_ = %s", name)
		}
	}
	if w.resumeStmt(ss[k], sc) {
		return true
	}
	return w.stmts(ss[k+1:], sc)
}

func (w *pipe) resumeStmt(s node, sc *env) bool {
	switch s := s.(type) {
	case *block:
		w.p("{")
		exits := w.resumeList(s.stmts, newEnv(sc))
		w.p("}")
		return exits
	case *ifStmt:
		// One switch for an else-if chain: a case for each branch that parse did not run.
		w.p("switch pkt.at {")
		exits := true
		for {
			then := w.onPath(s.then)
			off, path := s.els, s.then
			if !then {
				off, path = s.then, s.els
			}
			w.p("case %d:", w.at[s])
			if off == nil || !w.branch(off, sc) {
				exits = false
			}
			if next, ok := path.(*ifStmt); ok && !then {
				s = next
				continue
			}
			w.p("default:")
			exits = w.resumeList(stmtList(path), newEnv(sc)) && exits
			w.p("}")
			return exits
		}
	}
	// The split statement.
	var name string
	switch s := s.(type) {
	case *varDecl:
		name = w.declare(sc, s, s.name)
		sc.syms[s.name] = sym{name, s.typ}
		w.p("var %s %s = pkt.open", name, w.goType(s, s.typ))
	case *assign:
		name = w.expr(s.lhs, sc).code
		w.p("%s = pkt.open", name)
	}
	w.p("if %s == 0 {", name)
	w.p("%s = x.Opened(pkt, &pkt.m)", name)
	w.p("}")
	return false
}

// declare checks the name of a new local in sc and returns its Go name.
func (w *pipe) declare(sc *env, n node, name string) string {
	if _, ok := sc.lookup(name); ok {
		w.fail(n, "the local %s hides another name, which is not in the subset of the Go writer", name)
	}
	return w.goName(n, name, true)
}

// refers reports whether ns have the name.
func refers(ns []node, name string) bool {
	found := false
	for _, n := range ns {
		inspect(n, func(x node) bool {
			if id, ok := x.(*ident); ok && id.name == name {
				found = true
			}
			return !found
		})
	}
	return found
}

// reads reports whether ns read the local name. An assignment to it and the result of a meter
// are writes.
func reads(ns []node, name string) bool {
	found := false
	var f func(n node) bool
	f = func(n node) bool {
		if found {
			return false
		}
		switch n := n.(type) {
		case *ident:
			found = n.name == name
		case *assign:
			if id, ok := n.lhs.(*ident); ok && id.name == name {
				inspect(n.rhs, f)
				return false
			}
		case *call:
			if _, m, ok := n.method(); ok && m == "execute_meter" && len(n.args) == 2 {
				if id, ok := n.args[1].(*ident); ok && id.name == name {
					inspect(n.args[0], f)
					return false
				}
			}
		}
		return !found
	}
	for _, n := range ns {
		inspect(n, f)
	}
	return found
}

// stmts writes ss and reports whether the code exits. It stops after a statement that exits.
func (w *pipe) stmts(ss []node, sc *env) bool {
	for i, s := range ss {
		if w.stmt(s, sc, ss[i+1:]) {
			return true
		}
	}
	return false
}

// branch writes the statement or block n of an if.
func (w *pipe) branch(n node, sc *env) bool { return w.stmts(stmtList(n), newEnv(sc)) }

func (w *pipe) exit() {
	if w.inParse {
		w.parseExit = true
		w.p("pkt.at = atExit")
	}
	w.p("return")
}

// stmt writes s, with rest the statements after it in its block, and reports whether it exits.
func (w *pipe) stmt(s node, sc *env, rest []node) bool {
	switch s := s.(type) {
	case *block:
		w.p("{")
		exits := w.stmts(s.stmts, newEnv(sc))
		w.p("}")
		return exits
	case *varDecl:
		name := w.declare(sc, s, s.name)
		typ := w.goType(s, s.typ)
		if s.init != nil {
			w.p("var %s %s = %s", name, typ, w.value(s.init, s.typ, sc))
		} else {
			w.p("var %s %s", name, typ)
		}
		sc.syms[s.name] = sym{name, s.typ}
		if !reads(rest, s.name) {
			w.p("_ = %s", name)
		}
		return false
	case *assign:
		w.assign(s, sc)
		return false
	case *callStmt:
		return w.callStmt(s.call, sc)
	case *ifStmt:
		w.p("if %s {", w.expr(s.cond, sc).code)
		then := w.branch(s.then, sc)
		if s.els == nil {
			w.p("}")
			return false
		}
		w.p("} else {")
		els := w.branch(s.els, sc)
		w.p("}")
		return then && els
	case *exitStmt:
		w.exit()
		return true
	}
	w.fail(s, "this statement is not in the subset of the Go writer")
	return false
}

func (w *pipe) assign(s *assign, sc *env) {
	lhs := w.expr(s.lhs, sc)
	w.p("%s = %s", lhs.code, w.value(s.rhs, lhs.t, sc))
}

// value is the code of n as a value of type t: a list is a struct literal.
func (w *pipe) value(n node, t *typeRef, sc *env) string {
	l, ok := n.(*list)
	if !ok {
		if bt := w.base(t); bt.name == "bit" && bt.width > 64 {
			// A wide value has no Go constant: 0 is the zero value.
			if v, ok := w.prog.constValue(n); ok {
				if v.Sign() != 0 {
					w.fail(n, "a bit<%d> constant other than 0 is not in the subset of the Go writer", bt.width)
				}
				return w.goType(n, bt) + "{}"
			}
		}
		return w.expr(n, sc).code
	}
	st := w.prog.structType(w.base(t).name)
	if st == nil || st.header || len(l.elems) != len(st.fields) {
		w.fail(n, "a list is a value of a struct with the same number of fields in the subset of the Go writer")
	}
	var fs []string
	for i, f := range st.fields {
		fs = append(fs, w.fieldName(st, f)+": "+w.value(l.elems[i], f.typ, sc))
	}
	return w.structName(st.name) + "{" + strings.Join(fs, ", ") + "}"
}

func (w *pipe) callStmt(c *call, sc *env) bool {
	if id, ok := c.fun.(*ident); ok {
		switch {
		case id.name == "mark_to_drop":
			w.p("pkt.sm.egressSpec = p4DropPort")
			return false
		case w.prog.function(id.name) != nil:
			w.p("%s", w.callExpr(c, sc).code)
			return false
		}
		a := w.ctl.action(id.name)
		if a == nil {
			w.fail(c, "%s is not an action of %s", id.name, w.ctl.name)
		}
		if a.hidden && len(a.params) == 0 && len(a.body.stmts) == 0 {
			// A Go step of the runtime.
			w.p("if x.step%s(pkt) {", camel(a.name))
			w.exit()
			w.p("}")
			return false
		}
		return w.callAction(a, c.args, sc)
	}
	recv, name, named := c.method()
	if !named {
		h := w.expr(c.fun.(*member).x, sc)
		switch name {
		case "setValid":
			w.p("%s.valid = true", h.code)
			return false
		case "setInvalid":
			w.p("%s.valid = false", h.code)
			return false
		}
		w.fail(c, "%s as a statement is not in the subset of the Go writer", name)
	}
	if t := w.ctl.table(recv); t != nil {
		w.table(t)
		return false
	}
	in := w.ctl.instance(recv)
	if in == nil {
		w.fail(c, "%s.%s is not in the subset of the Go writer", recv, name)
	}
	switch in.typ {
	case "counter":
		w.p("x.countIndex(Counter%s, %s, pkt)", strings.TrimSuffix(camel(in.name), "Counter"), w.value(c.args[0], bitT(32), sc))
	case "meter":
		out := w.expr(c.args[1], sc)
		code := fmt.Sprintf("x.executeMeter(Meter%s, %s, pkt)", strings.TrimSuffix(camel(in.name), "Meter"), w.value(c.args[0], bitT(32), sc))
		if gt := w.goType(c, out.t); gt != "uint8" {
			code = gt + "(" + code + ")"
		}
		w.p("%s = %s", out.code, code)
	default:
		w.p("%s", w.callExpr(c, sc).code)
	}
	return false
}

// callAction writes the body of action a with its parameters set from args.
func (w *pipe) callAction(a *actionDecl, args []node, sc *env) bool {
	if len(args) != len(a.params) {
		w.fail(a, "action %s has %d parameters, not %d", a.name, len(a.params), len(args))
	}
	locals := map[string]bool{}
	inspect(a.body, func(n node) bool {
		if v, ok := n.(*varDecl); ok {
			locals[lowerCamel(v.name)] = true
		}
		return true
	})
	body := newEnv(w.root)
	var decls []string
	for i, prm := range a.params {
		e := w.expr(args[i], sc)
		if w.bindable(args[i], sc) && !locals[e.code] {
			body.syms[prm.name] = sym{e.code, prm.typ}
			continue
		}
		name := w.goName(prm, prm.name, true)
		decls = append(decls, fmt.Sprintf("var %s %s = %s", name, w.goType(prm, prm.typ), w.value(args[i], prm.typ, sc)))
		if !reads(a.body.stmts, prm.name) {
			decls = append(decls, "_ = "+name)
		}
		body.syms[prm.name] = sym{name, prm.typ}
	}
	return w.inline(a, decls, body)
}

// bindable reports whether the argument n can go into the body of an action as it is: a constant
// or a local, which the action cannot change.
func (w *pipe) bindable(n node, sc *env) bool {
	id, ok := n.(*ident)
	if !ok {
		return false
	}
	if s, ok := sc.lookup(id.name); ok {
		t := w.base(s.t)
		return t.name == "bit" || t.name == "bool" || t.name == "error"
	}
	return w.prog.constDecl(id.name) != nil
}

func (w *pipe) inline(a *actionDecl, decls []string, sc *env) bool {
	w.p("// %s", a.name)
	wrap := len(decls) > 0 || slices.ContainsFunc(a.body.stmts, func(s node) bool { _, ok := s.(*varDecl); return ok })
	if wrap {
		w.p("{")
	}
	for _, d := range decls {
		w.p("%s", d)
	}
	exits := w.stmts(a.body.stmts, sc)
	if wrap {
		w.p("}")
	}
	return exits
}

func (w *pipe) table(t *tableDecl) {
	var keys []string
	for _, k := range t.keys {
		keys = append(keys, w.expr(k.x, w.root).code)
	}
	look := fmt.Sprintf("x.st.lookup%s(%s)", camel(t.name), strings.Join(keys, ", "))
	dflt := t.dflt
	if dflt != nil && dflt.fun.(*ident).name == noAction {
		dflt = nil
	}
	if dflt == nil {
		w.p("if e := %s; e != nil {", look)
	} else {
		a := w.ctl.action(dflt.fun.(*ident).name)
		for _, prm := range a.params {
			if w.prog.newType(prm.typ.name) != nil {
				w.fail(dflt, "a default action with a translated parameter is not in the subset of the Go writer")
			}
		}
		w.p("if e := %s; e == nil {", look)
		w.callAction(a, dflt.args, w.root)
		w.p("} else {")
	}
	usesA := false
	for _, ai := range t.actions {
		if a := w.ctl.action(ai.name); a != nil {
			for _, prm := range a.params {
				usesA = usesA || w.prog.newType(prm.typ.name) == nil && reads(a.body.stmts, prm.name)
			}
		}
	}
	if usesA {
		w.p("switch a := e.action.(type) {")
	} else {
		w.p("switch e.action.(type) {")
	}
	for _, ai := range t.actions {
		if ai.name == noAction {
			w.p("case NoAction:")
			continue
		}
		a := w.ctl.action(ai.name)
		w.p("case %s:", actionType(a.name))
		sc := newEnv(w.root)
		for _, prm := range a.params {
			code := "a." + camel(prm.name)
			switch t := w.base(prm.typ); {
			case w.prog.newType(prm.typ.name) != nil:
				code = "e." + lowerCamel(prm.name)
			case t.name == "bit" && t.width == 1:
				w.usesBit = w.usesBit || reads(a.body.stmts, prm.name)
				code = "p4bit(" + code + ")"
			}
			sc.syms[prm.name] = sym{code, prm.typ}
		}
		w.inline(a, nil, sc)
	}
	w.p("}")
	w.p("}")
}

// Expressions.

func (w *pipe) expr(n node, sc *env) ex {
	e := w.expr1(n, sc)
	switch n.(type) {
	case *ident, *intLit, *boolLit:
		return e
	}
	// A constant expression is its value; a constant keeps its name.
	if v, ok := w.prog.constValue(n); ok {
		switch t := w.base(e.t); t.name {
		case "bool":
			return ex{strconv.FormatBool(v.Sign() != 0), e.t, true}
		case "int":
			return ex{lit(v), e.t, v.Sign() >= 0}
		case "bit":
			return ex{fmt.Sprintf("%s(%s)", w.goType(n, t), lit(v)), e.t, true}
		}
	}
	return e
}

func (w *pipe) expr1(n node, sc *env) ex {
	switch n := n.(type) {
	case *intLit:
		if n.width > 0 {
			return ex{fmt.Sprintf("%s(%s)", w.goType(n, bitT(n.width)), lit(n.val)), bitT(n.width), true}
		}
		return ex{lit(n.val), intT, n.val.Sign() >= 0}
	case *boolLit:
		return ex{strconv.FormatBool(n.val), boolT, true}
	case *errorLit:
		return ex{"p4Err" + n.name, errT, true}
	case *ident:
		if s, ok := sc.lookup(n.name); ok {
			return ex{s.code, s.t, true}
		}
		if c := w.prog.constDecl(n.name); c != nil {
			return ex{w.constName(c), c.typ, true}
		}
		w.fail(n, "%s is not a local, a parameter or a constant here", n.name)
	case *member:
		x := w.expr(n.x, sc)
		if x.t.name == "standard_metadata_t" {
			f, ok := smFields[n.name]
			if !ok {
				w.fail(n, "standard_metadata_t.%s is not in the subset of the Go writer", n.name)
			}
			return ex{x.code + "." + f.goName, f.t, true}
		}
		if s := w.prog.structType(w.base(x.t).name); s != nil {
			for _, f := range s.fields {
				if f.name == n.name {
					return ex{x.code + "." + w.fieldName(s, f), f.typ, true}
				}
			}
		}
		w.fail(n, "%s is not a field here", n.name)
	case *call:
		return w.callExpr(n, sc)
	case *unary:
		x := w.expr(n.x, sc)
		t := w.base(x.t)
		switch {
		case n.op == "!":
			return ex{"!" + x.operand(), boolT, true}
		case t.name == "int" && n.op == "-":
			return ex{"-" + x.operand(), intT, false}
		case t.name != "bit" || t.width > 64:
			w.fail(n, "%s of %s is not in the subset of the Go writer", n.op, typeText(x.t))
		case n.op == "~":
			return w.mask("^"+x.operand(), x.t, true)
		case n.op == "-":
			return w.mask("-"+x.operand(), x.t, true)
		}
	case *binary:
		return w.binary(n, sc)
	case *cond:
		for _, arm := range []node{n.t, n.f} {
			for _, cl := range calls(arm) {
				if _, name, _ := cl.method(); name != "isValid" {
					w.fail(cl, "a call in ?: is not in the subset of the Go writer")
				}
			}
		}
		c, a, b := w.expr(n.c, sc), w.expr(n.t, sc), w.expr(n.f, sc)
		t := a.t
		if w.base(t).name == "int" {
			t = b.t
		}
		if w.base(t).name == "int" {
			w.fail(n, "one side of ?: must have a type in the subset of the Go writer")
		}
		w.usesCond = true
		return ex{fmt.Sprintf("p4cond(%s, %s, %s)", c.code, a.code, b.code), t, true}
	case *cast:
		return w.cast(n, sc)
	}
	w.fail(n, "this expression is not in the subset of the Go writer")
	return ex{}
}

// mask clears the bits of code over the width of t, when that width is not a Go width.
func (w *pipe) mask(code string, t *typeRef, atom bool) ex {
	b := w.base(t)
	if b.name != "bit" || b.width == goBits(b.width) {
		return ex{code, t, atom}
	}
	if !atom {
		code = "(" + code + ")"
	}
	return ex{code + " & " + lit(ones(b.width)), t, false}
}

func (w *pipe) binary(n *binary, sc *env) ex {
	x, y := w.expr(n.x, sc), w.expr(n.y, sc)
	tx := w.base(x.t)
	t := x.t
	if tx.name == "int" {
		t = y.t
	}
	bt := w.base(t)
	code := x.operand() + " " + n.op + " " + y.operand()
	wide := bt.name == "bit" && bt.width > 64
	narrow := func() {
		if wide {
			w.fail(n, "bit<%d> has only == and != in the subset of the Go writer", bt.width)
		}
	}
	switch n.op {
	case "&&", "||":
		return ex{code, boolT, false}
	case "==", "!=":
		if !wide {
			return ex{code, boolT, false}
		}
		zero := func(e node) bool { v, ok := w.prog.constValue(e); return ok && v.Sign() == 0 }
		not := ""
		if n.op == "==" {
			not = "!"
		}
		switch {
		case bt.width == 144 && zero(n.y):
			return ex{not + x.operand() + ".IsValid()", boolT, true}
		case bt.width == 144 && zero(n.x):
			return ex{not + y.operand() + ".IsValid()", boolT, true}
		case tx.name == "bit" && w.base(y.t).name == "bit":
			return ex{code, boolT, false}
		}
		w.fail(n, "bit<%d> compares with the same type, or bit<144> with 0, in the subset of the Go writer", bt.width)
	case "<", ">", "<=", ">=":
		narrow()
		return ex{code, boolT, false}
	case ">>":
		if tx.name == "bit" && tx.width == 144 {
			if v, ok := w.prog.constUint(n.y); ok && v == 16 {
				return ex{x.operand() + ".Addr()", bitT(128), true}
			}
		}
		if tx.name == "bit" && tx.width > 64 {
			w.fail(n, "bit<%d> >> is only bit<144> >> 16 in the subset of the Go writer", tx.width)
		}
		return ex{code, x.t, false}
	case "<<":
		if tx.name == "bit" && tx.width > 64 {
			w.fail(n, "bit<%d> << is not in the subset of the Go writer", tx.width)
		}
		return w.mask(code, x.t, false)
	case "+", "-", "*":
		narrow()
		return w.mask(code, t, false)
	case "&", "|", "^", "/", "%":
		narrow()
		return ex{code, t, false}
	}
	w.fail(n, "the operator %s is not in the subset of the Go writer", n.op)
	return ex{}
}

func (w *pipe) cast(n *cast, sc *env) ex {
	x := w.expr(n.x, sc)
	from, to := w.base(x.t), w.base(n.to)
	switch {
	case to.name == "bool" && from.name == "bool":
		return ex{x.code, n.to, x.atom}
	case to.name == "bool" && from.name == "bit" && from.width == 1:
		return ex{x.operand() + " != 0", n.to, false}
	case to.name != "bit":
		w.fail(n, "a cast to %s is not in the subset of the Go writer", typeText(n.to))
	case from.name == "bool" && to.width == 1:
		w.usesBit = true
		return ex{"p4bit(" + x.code + ")", n.to, true}
	case from.name == "int" && to.width <= 64:
		v, _ := w.prog.constValue(n.x)
		return ex{fmt.Sprintf("%s(%s)", w.goType(n, to), lit(wrap(v, to.width))), n.to, true}
	case from.name == "bit" && from.width == 144 && to.width == 16:
		return ex{x.operand() + ".Port()", n.to, true}
	case from.name != "bit" || from.width > 64 || to.width > 64:
		w.fail(n, "a cast from %s to %s is not in the subset of the Go writer", typeText(x.t), typeText(n.to))
	}
	gt := w.goType(n, to)
	if gt == w.goType(n, from) && to.width >= from.width {
		return ex{x.code, n.to, x.atom}
	}
	code := gt + "(" + x.code + ")"
	if to.width < from.width && to.width != goBits(to.width) {
		return ex{code + " & " + lit(ones(to.width)), n.to, false}
	}
	return ex{code, n.to, true}
}

func (w *pipe) callExpr(c *call, sc *env) ex {
	if id, ok := c.fun.(*ident); ok {
		f := w.prog.function(id.name)
		if f == nil || len(c.args) != len(f.params) {
			w.fail(c, "a call of %s is not in the subset of the Go writer here", id.name)
		}
		args := []string{"pkt"}
		for i, prm := range f.params {
			if prm.dir == "out" {
				args = append(args, "&"+w.expr(c.args[i], sc).code)
			} else {
				args = append(args, w.value(c.args[i], prm.typ, sc))
			}
		}
		ret := f.ret
		if ret == nil {
			ret = voidT
		}
		return ex{fmt.Sprintf("%s(%s)", w.goName(f, f.name, false), strings.Join(args, ", ")), ret, true}
	}
	if code, ok := w.lookahead[c]; ok {
		return ex{code, c.typeArgs[0], true}
	}
	recv, name, named := c.method()
	if !named {
		if name == "isValid" {
			return ex{w.expr(c.fun.(*member).x, sc).operand() + ".valid", boolT, true}
		}
		w.fail(c, "%s in an expression is not in the subset of the Go writer", name)
	}
	if w.keys != nil && recv == w.keys.name && name != "open" {
		m := w.methodOf(name)
		if m == nil || len(c.args) != len(m.params) {
			w.fail(c, "%s.%s is not a method of %s", recv, name, pspSa)
		}
		w.pspCalls[name] = true
		var args []string
		for i, prm := range m.params {
			args = append(args, w.value(c.args[i], prm.typ, sc))
		}
		ret := m.ret
		if ret == nil {
			ret = voidT
		}
		return ex{fmt.Sprintf("x.%s(%s)", camel(name), strings.Join(args, ", ")), ret, true}
	}
	w.fail(c, "%s.%s in an expression is not in the subset of the Go writer", recv, name)
	return ex{}
}
