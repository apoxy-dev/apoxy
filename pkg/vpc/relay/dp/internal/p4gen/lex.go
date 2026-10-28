// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tInt
	tString
	tPunct
)

type token struct {
	kind  tokKind
	text  string
	line  int
	off   int      // Byte offset in the source.
	val   *big.Int // tInt.
	width int      // tInt: the N of an NwV literal, else 0.
}

// The includes that the subset accepts. p4gen knows the declarations it uses from them.
var includes = map[string]bool{"#include <core.p4>": true, "#include <v1model.p4>": true}

// Two-character operators. The lexer gives each '>' alone, so that `lookahead<bit<8>>()`
// closes two type lists; the expression parser joins '>' with a '>' or '=' next to it.
var punct2 = []string{"<<", "<=", "==", "!=", "&&", "||", ".."}

const punct1 = "{}()[]<>;:,.=+-*/%&|^~!?@"

// lex splits src into tokens. Comments and the accepted includes give no token.
func lex(file, src string) ([]token, error) {
	var toks []token
	line := 1
	errf := func(format string, args ...any) error {
		return fmt.Errorf("%s:%d: "+format, append([]any{file, line}, args...)...)
	}
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case strings.HasPrefix(src[i:], "//"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, errf("the comment has no end")
			}
			line += strings.Count(src[i:i+2+end], "\n")
			i += end + 4
		case c == '#':
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = len(src) - i
			}
			d, _, _ := strings.Cut(src[i:i+end], "//")
			if d = strings.Join(strings.Fields(d), " "); !includes[d] {
				return nil, errf("%q is not in the subset", d)
			}
			i += end
		case c == '"':
			end := strings.IndexAny(src[i+1:], "\"\\\n")
			if end < 0 || src[i+1+end] != '"' {
				return nil, errf("the string has no end, or has an escape")
			}
			toks = append(toks, token{kind: tString, text: src[i+1 : i+1+end], line: line, off: i})
			i += end + 2
		case isLetter(c):
			j := i
			for j < len(src) && (isLetter(src[j]) || isDigit(src[j])) {
				j++
			}
			toks = append(toks, token{kind: tIdent, text: src[i:j], line: line, off: i})
			i = j
		case isDigit(c):
			j := i
			for j < len(src) && (isLetter(src[j]) || isDigit(src[j])) {
				j++
			}
			t := token{kind: tInt, text: src[i:j], line: line, off: i}
			v, w, err := parseInt(t.text)
			if err != nil {
				return nil, errf("%v", err)
			}
			t.val, t.width = v, w
			toks = append(toks, t)
			i = j
		default:
			text := ""
			for _, p := range punct2 {
				if strings.HasPrefix(src[i:], p) {
					text = p
					break
				}
			}
			if text == "" && strings.IndexByte(punct1, c) >= 0 {
				text = src[i : i+1]
			}
			if text == "" {
				return nil, errf("character %q is not in the subset", c)
			}
			toks = append(toks, token{kind: tPunct, text: text, line: line, off: i})
			i += len(text)
		}
	}
	return append(toks, token{kind: tEOF, text: "end of file", line: line, off: len(src)}), nil
}

func isLetter(c byte) bool { return c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool  { return '0' <= c && c <= '9' }

// parseInt reads 10, 0x0a, 0b1010 and the width form 8w10. Underscores are ignored.
func parseInt(text string) (val *big.Int, width int, err error) {
	s := strings.ReplaceAll(text, "_", "")
	if i := strings.IndexByte(s, 'w'); i > 0 && !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		w, werr := strconv.Atoi(s[:i])
		if werr != nil || w <= 0 || w > 1<<16 {
			return nil, 0, fmt.Errorf("integer %q is not valid", text)
		}
		width, s = w, s[i+1:]
	}
	base := 10
	switch {
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		base, s = 16, s[2:]
	case strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B"):
		base, s = 2, s[2:]
	}
	val, ok := new(big.Int).SetString(s, base)
	if !ok || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		return nil, 0, fmt.Errorf("integer %q is not valid", text)
	}
	if width > 0 && val.BitLen() > width {
		return nil, 0, fmt.Errorf("integer %q does not fit in %d bits", text, width)
	}
	return val, width, nil
}
