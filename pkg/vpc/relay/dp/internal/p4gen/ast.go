// SPDX-License-Identifier: AGPL-3.0-only

package main

import "math/big"

// The AST of the P4 subset. Each node has the line of its first token.

type pos struct{ line int }

func (p pos) Line() int { return p.line }

// node is an expression or a statement.
type node interface{ Line() int }

type program struct {
	consts   []*constDecl
	newTypes []*newType
	structs  []*structType // Headers and structs, in source order.
	externs  []*externType
	funcs    []*method // The extern functions.
	parsers  []*parserDecl
	controls []*controlDecl
	main     *packageInst
}

// typeRef is bit<width>, bool or a declared type.
type typeRef struct {
	pos
	name  string
	width int
}

// Expressions.
type (
	ident struct {
		pos
		name string
	}
	member struct {
		pos
		x    node
		name string
	}
	intLit struct {
		pos
		val   *big.Int
		width int // 0: no width prefix.
	}
	boolLit struct {
		pos
		val bool
	}
	strLit struct { // Only in annotations.
		pos
		val string
	}
	call struct {
		pos
		fun      node // An ident (an action or a function) or a member (a method).
		typeArgs []*typeRef
		args     []node
	}
	unary struct {
		pos
		op string
		x  node
	}
	binary struct {
		pos
		op   string
		x, y node
	}
	cond struct {
		pos
		c, t, f node
	}
	cast struct {
		pos
		to *typeRef
		x  node
	}
	list struct {
		pos
		elems []node
	}
	// errorLit is error.name of core.p4.
	errorLit struct {
		pos
		name string
	}
	// rangeExpr is lo .. hi in a select case.
	rangeExpr struct {
		pos
		lo, hi node
	}
)

// Statements.
type (
	block struct {
		pos
		stmts []node
	}
	varDecl struct {
		pos
		typ  *typeRef
		name string
		init node // Can be nil.
	}
	assign struct {
		pos
		lhs, rhs node
	}
	callStmt struct {
		pos
		call *call
	}
	ifStmt struct {
		pos
		cond      node
		then, els node // els can be nil.
	}
	exitStmt struct{ pos }
)

// Declarations.
type (
	annotation struct {
		pos
		name string
		args []node
	}
	constDecl struct {
		pos
		typ  *typeRef
		name string
		val  node
	}
	// newType is `type bit<N> name;` with @p4runtime_translation(uri, string).
	newType struct {
		pos
		base      *typeRef
		name, uri string
	}
	structField struct {
		pos
		typ  *typeRef
		name string
	}
	structType struct {
		pos
		header     bool
		name       string
		controller string // The @controller_header name, or "".
		fields     []*structField
	}
	param struct {
		pos
		dir  string // in, out, inout or "".
		typ  *typeRef
		name string
	}
	method struct {
		pos
		ret    *typeRef // nil: void or a constructor.
		name   string
		params []*param
	}
	externType struct {
		pos
		name    string
		ctors   []*method
		methods []*method
	}
	actionDecl struct {
		pos
		name   string
		hidden bool
		params []*param
		body   *block
	}
	keyElem struct {
		pos
		x     node // A path such as m.p.session.
		match string
	}
	tableDecl struct {
		pos
		name      string
		keys      []*keyElem
		actions   []*ident
		dflt      *call // nil: NoAction, as p4c adds it.
		dfltConst bool
		size      node // Can be nil.
	}
	// instance is `counter(...) name;`, `meter(...) name;` or `PspSa(...) name;`.
	instance struct {
		pos
		typ  string
		args []node
		name string
	}
	controlDecl struct {
		pos
		name      string
		params    []*param
		actions   []*actionDecl
		tables    []*tableDecl
		instances []*instance
		apply     *block
	}
	selectCase struct {
		pos
		val node // nil: default.
		to  string
	}
	transition struct {
		pos
		to    string // When sel is nil.
		sel   node
		cases []*selectCase
	}
	parserState struct {
		pos
		name  string
		stmts []node
		next  *transition
	}
	parserDecl struct {
		pos
		name   string
		params []*param
		states []*parserState
	}
	// packageInst is `V1Switch(P(), ...) main;`.
	packageInst struct {
		pos
		typ  string
		args []string
		name string
	}
)

// inspect calls f for n and, while f returns true, for each node in n.
func inspect(n node, f func(node) bool) {
	if n == nil || !f(n) {
		return
	}
	each := func(ns ...node) {
		for _, x := range ns {
			inspect(x, f)
		}
	}
	switch n := n.(type) {
	case *member:
		each(n.x)
	case *call:
		each(n.fun)
		each(n.args...)
	case *unary:
		each(n.x)
	case *binary:
		each(n.x, n.y)
	case *cond:
		each(n.c, n.t, n.f)
	case *cast:
		each(n.x)
	case *list:
		each(n.elems...)
	case *rangeExpr:
		each(n.lo, n.hi)
	case *block:
		each(n.stmts...)
	case *varDecl:
		if n.init != nil {
			each(n.init)
		}
	case *assign:
		each(n.lhs, n.rhs)
	case *callStmt:
		each(n.call)
	case *ifStmt:
		each(n.cond, n.then)
		if n.els != nil {
			each(n.els)
		}
	}
}

// calls returns the calls in n, in source order.
func calls(n node) []*call {
	var cs []*call
	inspect(n, func(x node) bool {
		if c, ok := x.(*call); ok {
			cs = append(cs, c)
		}
		return true
	})
	return cs
}

// method returns the receiver name and the method of c, if c calls a method of a named object.
func (c *call) method() (recv, name string, ok bool) {
	m, isMember := c.fun.(*member)
	if !isMember {
		return "", "", false
	}
	id, isIdent := m.x.(*ident)
	if !isIdent {
		return "", m.name, false
	}
	return id.name, m.name, true
}

// path returns the dotted text of n, if n is a name or a chain of members.
func path(n node) (string, bool) {
	switch n := n.(type) {
	case *ident:
		return n.name, true
	case *member:
		x, ok := path(n.x)
		return x + "." + n.name, ok
	}
	return "", false
}
