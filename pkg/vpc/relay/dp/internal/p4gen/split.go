// SPDX-License-Identifier: AGPL-3.0-only

package main

// splitPoint is where parse ends and apply starts in the control of the PspSa instance: the
// statement in the first if of apply that sets a local to the result of keys.open.
type splitPoint struct {
	ctl   *controlDecl
	first *ifStmt // The first if of apply.
	stmt  node    // The varDecl or the assign of the call.
	local string  // The local that the call sets; apply starts with its value.
}

// split finds the split point of prog, or nil if no control calls the open method of its
// PspSa instance. The call must set a local in the first if of apply, before any table apply,
// meter, counter or other PspSa call; else it is an error.
func split(file string, prog *program) (*splitPoint, error) {
	for _, c := range prog.mainControls() {
		for _, in := range c.instances {
			if in.typ != pspSa {
				continue
			}
			sp, err := splitControl(file, c, in.name)
			if sp != nil || err != nil {
				return sp, err
			}
		}
	}
	return nil, nil
}

func splitControl(file string, c *controlDecl, keys string) (*splitPoint, error) {
	isOpen := func(cl *call) bool {
		recv, name, ok := cl.method()
		return ok && recv == keys && name == "open"
	}
	var opens []*call
	for _, a := range c.actions {
		for _, cl := range calls(a.body) {
			if isOpen(cl) {
				return nil, errAt(file, cl, "%s.open must be in apply, not in action %s", keys, a.name)
			}
		}
	}
	for _, cl := range calls(c.apply) {
		if isOpen(cl) {
			opens = append(opens, cl)
		}
	}
	if len(opens) == 0 {
		return nil, nil
	}
	if len(opens) > 1 {
		return nil, errAt(file, opens[1], "%s.open is called %d times; the split needs one call", keys, len(opens))
	}
	open := opens[0]
	first := firstIf(c.apply.stmts)
	if first == nil || !contains(first, open) {
		return nil, errAt(file, open, "%s.open must be in the first if of apply", keys)
	}
	w := &splitWalk{target: open, locals: map[string]bool{}}
	w.stmts(c.apply.stmts)
	local := ""
	switch s := w.found.(type) {
	case *varDecl:
		if s.init == open {
			local = s.name
		}
	case *assign:
		if id, ok := s.lhs.(*ident); ok && s.rhs == open && w.locals[id.name] {
			local = id.name
		}
	}
	if local == "" {
		return nil, errAt(file, open, "%s.open must set a local: `bit<8> r = %s.open(...);` or `r = %s.open(...);`", keys, keys, keys)
	}
	// The arguments of the call run before it too.
	for _, n := range append(w.before, open.args...) {
		if bad := firstWork(c, keys, n, map[string]bool{}); bad != nil {
			return nil, errAt(file, bad, "parse runs this before %s.open; a table apply, a meter, a counter or a %s call must come after it", keys, pspSa)
		}
	}
	return &splitPoint{ctl: c, first: first, stmt: w.found, local: local}, nil
}

// firstIf returns the first if of ss, also in a block of ss.
func firstIf(ss []node) *ifStmt {
	for _, s := range ss {
		switch s := s.(type) {
		case *ifStmt:
			return s
		case *block:
			if f := firstIf(s.stmts); f != nil {
				return f
			}
		}
	}
	return nil
}

func contains(n node, target *call) bool {
	found := false
	inspect(n, func(x node) bool {
		found = found || x == target
		return !found
	})
	return found
}

// splitWalk goes through the statements of apply in order up to the statement of target. It
// keeps the statements and conditions that run before it, and the locals that they declare.
type splitWalk struct {
	target *call
	before []node
	locals map[string]bool
	found  node
}

func (w *splitWalk) stmts(ss []node) bool {
	for _, s := range ss {
		if w.stmt(s) {
			return true
		}
	}
	return false
}

func (w *splitWalk) stmt(s node) bool {
	if !contains(s, w.target) {
		w.before = append(w.before, s)
		if v, ok := s.(*varDecl); ok {
			w.locals[v.name] = true
		}
		return false
	}
	switch s := s.(type) {
	case *block:
		return w.stmts(s.stmts)
	case *ifStmt:
		if contains(s.cond, w.target) {
			w.found = s
			return true
		}
		w.before = append(w.before, s.cond)
		if contains(s.then, w.target) {
			return w.stmt(s.then)
		}
		return w.stmt(s.els) // The then branch does not run on this path.
	}
	w.found = s
	return true
}

// firstWork returns the first call in n that applies a table, uses a meter or a counter, or
// calls a method of keys, also in the actions that n calls.
func firstWork(c *controlDecl, keys string, n node, seen map[string]bool) node {
	for _, cl := range calls(n) {
		if recv, _, ok := cl.method(); ok {
			if c.table(recv) != nil || recv == keys {
				return cl
			}
			if in := c.instance(recv); in != nil && (in.typ == "counter" || in.typ == "meter") {
				return cl
			}
			continue
		}
		if id, ok := cl.fun.(*ident); ok && !seen[id.name] {
			seen[id.name] = true
			if a := c.action(id.name); a != nil && firstWork(c, keys, a.body, seen) != nil {
				return cl
			}
		}
	}
	return nil
}
