// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// The P4 keywords that the subset does not use as names.
var keywords = map[string]bool{
	"action": true, "apply": true, "bit": true, "bool": true, "const": true, "control": true,
	"default": true, "else": true, "enum": true, "error": true, "exit": true, "extern": true,
	"false": true, "header": true, "header_union": true, "if": true, "in": true, "inout": true,
	"int": true, "list": true, "match_kind": true, "out": true, "package": true, "parser": true,
	"return": true, "select": true, "state": true, "string": true, "struct": true, "switch": true,
	"table": true, "transition": true, "true": true, "tuple": true, "type": true, "typedef": true,
	"value_set": true, "varbit": true, "void": true,
}

// parseError is the panic value of parser.failf; parse recovers it.
type parseError struct{ err error }

type parser struct {
	file string
	toks []token
	i    int
}

// parse reads a P4 program of the subset. Any other construct is an error with the file and line.
func parse(file, src string) (prog *program, err error) {
	toks, err := lex(file, src)
	if err != nil {
		return nil, err
	}
	p := &parser{file: file, toks: toks}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(parseError)
			if !ok {
				panic(r)
			}
			prog, err = nil, pe.err
		}
	}()
	prog = p.program()
	if err := check(file, prog); err != nil {
		return nil, err
	}
	return prog, nil
}

func (p *parser) failf(line int, format string, args ...any) {
	panic(parseError{fmt.Errorf("%s:%d: "+format, append([]any{p.file, line}, args...)...)})
}

func (p *parser) peek() token        { return p.toks[p.i] }
func (p *parser) peekAt(n int) token { return p.toks[min(p.i+n, len(p.toks)-1)] }

// next reads a token. At the end it gives the EOF token again, so each caller fails with a line.
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}
func (p *parser) is(text string) bool {
	t := p.peek()
	return t.kind != tString && t.text == text
}

func (p *parser) accept(text string) bool {
	if p.is(text) {
		p.i++
		return true
	}
	return false
}

func (p *parser) expect(text string) token {
	t := p.peek()
	if !p.is(text) {
		p.failf(t.line, "found %q, want %q", t.text, text)
	}
	return p.next()
}

// name reads an identifier that is not a keyword.
func (p *parser) name() token {
	t := p.next()
	if t.kind != tIdent {
		p.failf(t.line, "found %q, want a name", t.text)
	}
	if keywords[t.text] {
		p.failf(t.line, "%q is not in the subset here", t.text)
	}
	// p4c reads _ as "any value", and keeps a declaration that starts with __ when it is not used.
	if t.text == "_" || strings.HasPrefix(t.text, "__") {
		p.failf(t.line, "the name %q is not in the subset", t.text)
	}
	return t
}

func (p *parser) program() *program {
	prog := &program{}
	for p.peek().kind != tEOF {
		anns := p.annotations()
		t := p.peek()
		switch {
		case p.is("const"):
			p.only(anns)
			prog.consts = append(prog.consts, p.constDecl())
		case p.is("type"):
			prog.newTypes = append(prog.newTypes, p.newType(anns))
		case p.is("header") || p.is("struct"):
			prog.structs = append(prog.structs, p.structType(anns))
		case p.is("extern"):
			p.only(anns)
			prog.externs = append(prog.externs, p.externType())
		case p.is("control"):
			p.only(anns)
			prog.controls = append(prog.controls, p.control())
		case p.is("parser"):
			p.only(anns)
			prog.parsers = append(prog.parsers, p.parserDecl())
		case t.kind == tIdent && !keywords[t.text] && p.peekAt(1).text == "(":
			p.only(anns)
			if prog.main != nil {
				p.failf(t.line, "a second package instance is not in the subset")
			}
			prog.main = p.packageInst()
		default:
			p.failf(t.line, "%q at the top level is not in the subset", t.text)
		}
	}
	if prog.main == nil {
		p.failf(p.peek().line, "the program has no V1Switch package instance")
	}
	return prog
}

// annotations reads @name or @name(args) with strings and names as the arguments.
func (p *parser) annotations() []*annotation {
	var anns []*annotation
	for p.is("@") {
		at := p.next()
		n := p.next()
		if n.kind != tIdent {
			p.failf(n.line, "found %q, want an annotation name", n.text)
		}
		a := &annotation{pos: pos{at.line}, name: n.text}
		if p.accept("(") {
			for !p.accept(")") {
				if len(a.args) > 0 {
					p.expect(",")
				}
				t := p.next()
				switch t.kind {
				case tString:
					a.args = append(a.args, &strLit{pos{t.line}, t.text})
				case tIdent:
					a.args = append(a.args, &ident{pos{t.line}, t.text})
				default:
					p.failf(t.line, "annotation argument %q is not in the subset", t.text)
				}
			}
		}
		anns = append(anns, a)
	}
	return anns
}

// only fails on each annotation that is not in allowed, and on an annotation that is there
// two times.
func (p *parser) only(anns []*annotation, allowed ...string) {
	for i, a := range anns {
		if !slices.Contains(allowed, a.name) {
			p.failf(a.line, "annotation @%s is not in the subset here", a.name)
		}
		if slices.ContainsFunc(anns[:i], func(b *annotation) bool { return b.name == a.name }) {
			p.failf(a.line, "annotation @%s is there two times", a.name)
		}
	}
}

// stringArg returns the one string argument of a.
func (p *parser) stringArg(a *annotation) string {
	if len(a.args) != 1 {
		p.failf(a.line, "@%s must have one string argument", a.name)
	}
	s, ok := a.args[0].(*strLit)
	if !ok || s.val == "" {
		p.failf(a.line, "@%s must have one string argument that is not empty", a.name)
	}
	return s.val
}

func (p *parser) typeRef() *typeRef {
	t := p.next()
	switch {
	case t.kind == tIdent && t.text == "bit":
		p.expect("<")
		w := p.next()
		if w.kind != tInt || w.width != 0 || w.val.Sign() == 0 || w.val.Cmp(big.NewInt(1<<16)) > 0 {
			p.failf(w.line, "bit<%s> is not in the subset", w.text)
		}
		p.expect(">")
		return &typeRef{pos: pos{t.line}, name: "bit", width: int(w.val.Int64())}
	case t.kind == tIdent && t.text == "bool":
		return &typeRef{pos: pos{t.line}, name: "bool"}
	case t.kind == tIdent && !keywords[t.text]:
		return &typeRef{pos: pos{t.line}, name: t.text}
	}
	p.failf(t.line, "type %q is not in the subset", t.text)
	return nil
}

func (p *parser) constDecl() *constDecl {
	t := p.expect("const")
	c := &constDecl{pos: pos{t.line}, typ: p.typeRef(), name: p.name().text}
	p.expect("=")
	c.val = p.expr()
	p.expect(";")
	return c
}

func (p *parser) newType(anns []*annotation) *newType {
	t := p.expect("type")
	p.only(anns, "p4runtime_translation")
	n := &newType{pos: pos{t.line}, base: p.typeRef(), name: p.name().text}
	p.expect(";")
	if len(anns) != 1 || len(anns[0].args) != 2 {
		p.failf(t.line, "type %s needs @p4runtime_translation(uri, string)", n.name)
	}
	uri, ok1 := anns[0].args[0].(*strLit)
	str, ok2 := anns[0].args[1].(*ident)
	if !ok1 || !ok2 || str.name != "string" {
		p.failf(t.line, "type %s: only @p4runtime_translation(uri, string) is in the subset", n.name)
	}
	n.uri = uri.val
	return n
}

func (p *parser) structType(anns []*annotation) *structType {
	t := p.next()
	s := &structType{pos: pos{t.line}, header: t.text == "header"}
	if s.header {
		p.only(anns, "controller_header")
		if len(anns) == 1 {
			s.controller = p.stringArg(anns[0])
		}
	} else {
		p.only(anns)
	}
	s.name = p.name().text
	p.expect("{")
	for !p.accept("}") {
		p.only(p.annotations())
		f := &structField{pos: pos{p.peek().line}, typ: p.typeRef(), name: p.name().text}
		p.expect(";")
		s.fields = append(s.fields, f)
	}
	return s
}

// params reads (param, ...). A direction is optional.
func (p *parser) params() []*param {
	p.expect("(")
	var ps []*param
	for !p.accept(")") {
		if len(ps) > 0 {
			p.expect(",")
		}
		p.only(p.annotations())
		prm := &param{pos: pos{p.peek().line}}
		if p.is("in") || p.is("out") || p.is("inout") {
			prm.dir = p.next().text
		}
		prm.typ = p.typeRef()
		prm.name = p.name().text
		ps = append(ps, prm)
	}
	return ps
}

func (p *parser) externType() *externType {
	t := p.expect("extern")
	e := &externType{pos: pos{t.line}, name: p.name().text}
	p.expect("{")
	for !p.accept("}") {
		p.only(p.annotations())
		m := &method{pos: pos{p.peek().line}}
		switch {
		case p.is(e.name) && p.peekAt(1).text == "(":
			m.name = p.next().text
			m.params = p.params()
			e.ctors = append(e.ctors, m)
		case p.accept("void"):
			m.name = p.name().text
			m.params = p.params()
			e.methods = append(e.methods, m)
		default:
			m.ret = p.typeRef()
			m.name = p.name().text
			m.params = p.params()
			e.methods = append(e.methods, m)
		}
		p.expect(";")
	}
	return e
}

func (p *parser) control() *controlDecl {
	t := p.expect("control")
	c := &controlDecl{pos: pos{t.line}, name: p.name().text}
	c.params = p.params()
	p.expect("{")
	for c.apply == nil {
		anns := p.annotations()
		t := p.peek()
		switch {
		case p.is("action"):
			p.only(anns, "hidden")
			a := p.action()
			a.hidden = len(anns) > 0
			c.actions = append(c.actions, a)
		case p.is("table"):
			p.only(anns)
			c.tables = append(c.tables, p.table())
		case p.is("apply"):
			p.only(anns)
			p.next()
			c.apply = p.block(false)
		case t.kind == tIdent && !keywords[t.text] && p.peekAt(1).text == "(":
			p.only(anns)
			c.instances = append(c.instances, p.instance())
		default:
			p.failf(t.line, "%q in a control is not in the subset", t.text)
		}
	}
	p.expect("}")
	return c
}

func (p *parser) action() *actionDecl {
	t := p.expect("action")
	a := &actionDecl{pos: pos{t.line}, name: p.name().text}
	if a.name == noAction {
		p.failf(t.line, "an action named %s is not in the subset; core.p4 declares it", noAction)
	}
	a.params = p.params()
	for _, prm := range a.params {
		if prm.dir != "" {
			p.failf(prm.line, "an action parameter with a direction is not in the subset")
		}
	}
	a.body = p.block(false)
	return a
}

func (p *parser) table() *tableDecl {
	t := p.expect("table")
	tb := &tableDecl{pos: pos{t.line}, name: p.name().text}
	p.expect("{")
	seen := map[string]bool{}
	for !p.accept("}") {
		pt := p.peek()
		isConst := p.accept("const")
		prop := p.next()
		if prop.kind != tIdent {
			p.failf(prop.line, "found %q, want a table property", prop.text)
		}
		if seen[prop.text] {
			p.failf(prop.line, "table %s has two %s properties", tb.name, prop.text)
		}
		seen[prop.text] = true
		if isConst && prop.text != "default_action" {
			p.failf(pt.line, "const %s is not in the subset", prop.text)
		}
		p.expect("=")
		switch prop.text {
		case "key":
			p.expect("{")
			for !p.accept("}") {
				k := &keyElem{pos: pos{p.peek().line}, x: p.expr()}
				if _, ok := path(k.x); !ok {
					p.failf(k.line, "a key must be a field path")
				}
				p.expect(":")
				m := p.next()
				if m.kind != tIdent || m.text != "exact" && m.text != "lpm" {
					p.failf(m.line, "match kind %q is not in the subset", m.text)
				}
				k.match = m.text
				p.expect(";")
				tb.keys = append(tb.keys, k)
			}
		case "actions":
			p.expect("{")
			for !p.accept("}") {
				p.only(p.annotations())
				n := p.name()
				tb.actions = append(tb.actions, &ident{pos{n.line}, n.text})
				p.expect(";")
			}
		case "default_action":
			n := p.name()
			tb.dflt = &call{pos: pos{n.line}, fun: &ident{pos{n.line}, n.text}}
			if p.is("(") {
				tb.dflt.args = p.args()
			}
			tb.dfltConst = isConst
			p.expect(";")
		case "size":
			tb.size = p.expr()
			p.expect(";")
		default:
			p.failf(prop.line, "table property %q is not in the subset", prop.text)
		}
	}
	if !seen["key"] || !seen["actions"] {
		p.failf(t.line, "table %s needs key and actions", tb.name)
	}
	return tb
}

func (p *parser) instance() *instance {
	t := p.name()
	in := &instance{pos: pos{t.line}, typ: t.text, args: p.args()}
	in.name = p.name().text
	p.expect(";")
	return in
}

func (p *parser) parserDecl() *parserDecl {
	t := p.expect("parser")
	d := &parserDecl{pos: pos{t.line}, name: p.name().text}
	d.params = p.params()
	p.expect("{")
	for !p.accept("}") {
		p.only(p.annotations())
		st := p.expect("state")
		s := &parserState{pos: pos{st.line}, name: p.name().text}
		p.expect("{")
		for !p.is("transition") {
			s.stmts = append(s.stmts, p.stmt(true))
		}
		tt := p.next()
		s.next = &transition{pos: pos{tt.line}}
		if p.accept("select") {
			p.expect("(")
			s.next.sel = p.expr()
			p.expect(")")
			p.expect("{")
			for !p.accept("}") {
				c := &selectCase{pos: pos{p.peek().line}}
				if !p.accept("default") {
					c.val = p.expr()
				}
				p.expect(":")
				c.to = p.name().text
				p.expect(";")
				s.next.cases = append(s.next.cases, c)
			}
		} else {
			s.next.to = p.name().text
			p.expect(";")
		}
		p.expect("}")
		d.states = append(d.states, s)
	}
	return d
}

func (p *parser) packageInst() *packageInst {
	t := p.name()
	pk := &packageInst{pos: pos{t.line}, typ: t.text}
	p.expect("(")
	for !p.accept(")") {
		if len(pk.args) > 0 {
			p.expect(",")
		}
		pk.args = append(pk.args, p.name().text)
		p.expect("(")
		p.expect(")")
	}
	pk.name = p.name().text
	p.expect(";")
	return pk
}

// block reads { statements }.
func (p *parser) block(inParser bool) *block {
	t := p.expect("{")
	b := &block{pos: pos{t.line}}
	for !p.accept("}") {
		b.stmts = append(b.stmts, p.stmt(inParser))
	}
	return b
}

// stmt reads one statement. A parser state has no if, exit or block.
func (p *parser) stmt(inParser bool) node {
	t := p.peek()
	switch {
	case !inParser && p.is("{"):
		return p.block(false)
	case !inParser && p.accept("if"):
		s := &ifStmt{pos: pos{t.line}}
		p.expect("(")
		s.cond = p.expr()
		p.expect(")")
		s.then = p.stmt(false)
		if p.accept("else") {
			s.els = p.stmt(false)
		}
		return s
	case !inParser && p.accept("exit"):
		p.expect(";")
		return &exitStmt{pos{t.line}}
	case p.is("bit") || p.is("bool") || t.kind == tIdent && !keywords[t.text] && p.peekAt(1).kind == tIdent:
		v := &varDecl{pos: pos{t.line}, typ: p.typeRef(), name: p.name().text}
		if p.accept("=") {
			v.init = p.expr()
		}
		p.expect(";")
		return v
	}
	x := p.expr()
	if p.accept("=") {
		if _, ok := path(x); !ok {
			p.failf(t.line, "the left side of an assignment must be a field path")
		}
		s := &assign{pos: pos{t.line}, lhs: x, rhs: p.expr()}
		p.expect(";")
		return s
	}
	c, ok := x.(*call)
	if !ok {
		p.failf(t.line, "a statement must be a call or an assignment")
	}
	p.expect(";")
	return &callStmt{pos{t.line}, c}
}

// Binary operators by precedence, low to high, as in the p4c grammar: the bit operators bind
// tighter than the comparisons.
var binaryOps = [][]string{
	{"||"}, {"&&"}, {"==", "!="}, {"<", ">", "<=", ">="}, {"|"}, {"^"}, {"&"}, {"<<", ">>"}, {"+", "-"}, {"*", "/", "%"},
}

func (p *parser) expr() node {
	x := p.binary(0)
	if t := p.peek(); p.accept("?") {
		c := &cond{pos: pos{t.line}, c: x, t: p.expr()}
		p.expect(":")
		c.f = p.expr()
		return c
	}
	return x
}

// op returns the binary operator at the cursor and its token count. It joins '>' with a '>' or
// '=' that is next to it.
func (p *parser) op() (string, int) {
	t := p.peek()
	if t.kind != tPunct {
		return "", 0
	}
	if n := p.peekAt(1); t.text == ">" && n.kind == tPunct && n.off == t.off+1 && (n.text == ">" || n.text == "=") {
		return ">" + n.text, 2
	}
	return t.text, 1
}

func (p *parser) binary(level int) node {
	if level == len(binaryOps) {
		return p.unaryExpr()
	}
	x := p.binary(level + 1)
	for {
		op, n := p.op()
		if !slices.Contains(binaryOps[level], op) {
			return x
		}
		t := p.peek()
		p.i += n
		x = &binary{pos: pos{t.line}, op: op, x: x, y: p.binary(level + 1)}
	}
}

func (p *parser) unaryExpr() node {
	t := p.peek()
	if p.is("!") || p.is("~") || p.is("-") {
		p.next()
		return &unary{pos: pos{t.line}, op: t.text, x: p.unaryExpr()}
	}
	return p.postfix(p.primary())
}

func (p *parser) primary() node {
	t := p.next()
	switch {
	case t.kind == tInt:
		return &intLit{pos{t.line}, t.val, t.width}
	case t.kind == tIdent && (t.text == "true" || t.text == "false"):
		return &boolLit{pos{t.line}, t.text == "true"}
	case t.kind == tIdent && !keywords[t.text]:
		return &ident{pos{t.line}, t.text}
	case t.kind == tPunct && t.text == "(":
		if p.is("bit") || p.is("bool") {
			c := &cast{pos: pos{t.line}, to: p.typeRef()}
			p.expect(")")
			c.x = p.unaryExpr()
			return c
		}
		x := p.expr()
		p.expect(")")
		return x
	case t.kind == tPunct && t.text == "{":
		l := &list{pos: pos{t.line}}
		for !p.accept("}") {
			if len(l.elems) > 0 {
				p.expect(",")
			}
			l.elems = append(l.elems, p.expr())
		}
		return l
	}
	p.failf(t.line, "%q is not in the subset here", t.text)
	return nil
}

// postfix reads members and calls after x. A call ends the expression: the subset has no
// member of a call result, such as t.apply().hit.
func (p *parser) postfix(x node) node {
	if c, ok := x.(*call); ok { // A call in parentheses.
		return p.end(c)
	}
	for {
		t := p.peek()
		switch {
		case p.accept("."):
			n := p.next()
			if n.kind != tIdent {
				p.failf(n.line, "found %q, want a member name", n.text)
			}
			x = &member{pos: pos{t.line}, x: x, name: n.text}
			var targs []*typeRef
			if p.is("<") && p.try(func() { targs = p.typeArgs() }) {
				c := &call{pos: pos{t.line}, fun: x, typeArgs: targs, args: p.args()}
				return p.end(c)
			}
		case p.is("("):
			return p.end(&call{pos: pos{t.line}, fun: x, args: p.args()})
		case p.is("["):
			p.failf(t.line, "an index or a slice is not in the subset")
		default:
			return x
		}
	}
}

func (p *parser) end(c *call) node {
	if t := p.peek(); p.is(".") || p.is("(") || p.is("[") {
		p.failf(t.line, "a member or a call of a call result is not in the subset")
	}
	return c
}

// typeArgs reads <T, ...> that a call follows.
func (p *parser) typeArgs() []*typeRef {
	p.expect("<")
	var ts []*typeRef
	for {
		ts = append(ts, p.typeRef())
		if !p.accept(",") {
			break
		}
	}
	p.expect(">")
	if !p.is("(") {
		p.failf(p.peek().line, "want a call after the type arguments")
	}
	return ts
}

// try runs f and reports whether it read its tokens with no error. On an error the cursor goes back.
func (p *parser) try(f func()) (ok bool) {
	save := p.i
	defer func() {
		if r := recover(); r != nil {
			if _, isParse := r.(parseError); !isParse {
				panic(r)
			}
			p.i, ok = save, false
		}
	}()
	f()
	return true
}

func (p *parser) args() []node {
	p.expect("(")
	var as []node
	for !p.accept(")") {
		if len(as) > 0 {
			p.expect(",")
		}
		as = append(as, p.expr())
	}
	return as
}
