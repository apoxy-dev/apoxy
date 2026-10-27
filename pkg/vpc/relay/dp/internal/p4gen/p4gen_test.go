// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"
)

// p4case is a case of TestP4gen, from a txtar file in testdata/cases. The comment of the archive
// has the expectations, one "key: value" per line; a line that starts with # is a note. The files
// of the archive are prog.p4, the program, and p4info.txtpb, the P4Info text that it must give.
type p4case struct {
	name    string            // name: the name of the subtest.
	srcName string            // The file name in the errors: prog.p4, or the base name of file:.
	src     string            // prog.p4, or the text of file:, a program outside testdata.
	wantErr string            // error: a part of the error after "file:line: "; "// here" marks the line.
	info    string            // p4info.txtpb, or the text of the file at the path info:.
	gen     string            // gen: the Go file that the generated code must be.
	ids     map[string]uint32 // ids: name=ID pairs; each ids line adds to the map.
	local   string            // local: the local of the split; "" for no split.
}

// readCase reads the case in the txtar file path. With "nonewline: true", prog.p4 has no newline
// at the end (txtar adds one), so that the end of the file is on the line of the last text.
func readCase(t *testing.T, path string) p4case {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	a := txtar.Parse(b)
	tc := p4case{srcName: "prog.p4"}
	var file, info string
	noNewline := false
	for _, l := range strings.Split(string(a.Comment), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, ": ")
		require.True(t, ok, "%s: %q is not a key: value line", path, l)
		switch k {
		case "name":
			tc.name = v
		case "file":
			file = v
		case "error":
			tc.wantErr = v
		case "info":
			info = v
		case "gen":
			tc.gen = v
		case "local":
			tc.local = v
		case "ids":
			if tc.ids == nil {
				tc.ids = map[string]uint32{}
			}
			for _, f := range strings.Fields(v) {
				n, s, _ := strings.Cut(f, "=")
				id, err := strconv.ParseUint(s, 0, 32)
				require.NoError(t, err, "%s: ids %s", path, f)
				tc.ids[n] = uint32(id)
			}
		case "nonewline":
			noNewline, err = strconv.ParseBool(v)
			require.NoError(t, err, path)
		default:
			t.Fatalf("%s: the key %q is not known", path, k)
		}
	}
	for _, f := range a.Files {
		switch f.Name {
		case "prog.p4":
			tc.src = string(f.Data)
		case "p4info.txtpb":
			tc.info = string(f.Data)
		default:
			t.Fatalf("%s: the file %s is not known", path, f.Name)
		}
	}
	if file != "" {
		b, err := os.ReadFile(file)
		require.NoError(t, err)
		tc.srcName, tc.src = filepath.Base(file), string(b)
	}
	if info != "" {
		b, err := os.ReadFile(info)
		require.NoError(t, err)
		tc.info = string(b)
	}
	if noNewline {
		tc.src = strings.TrimSuffix(tc.src, "\n")
	}
	require.NotEmpty(t, tc.name, "%s has no name", path)
	require.NotEmpty(t, tc.src, "%s has no program", path)
	return tc
}

func TestP4gen(t *testing.T) {
	paths, err := filepath.Glob("testdata/cases/*.txtar")
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	for _, path := range paths {
		tc := readCase(t, path)
		t.Run(tc.name, func(t *testing.T) {
			name, src := tc.srcName, tc.src
			prog, c, err := load(name, src)
			if tc.wantErr != "" {
				line := strings.Count(src[:strings.Index(src, "// here")], "\n") + 1
				require.Error(t, err)
				assert.Contains(t, err.Error(), fmt.Sprintf("%s:%d: %s", name, line, tc.wantErr))
				return
			}
			require.NoError(t, err)
			_, err = goCode(prog, c, name, "dp")
			require.NoError(t, err)
			sp, err := split(name, prog)
			require.NoError(t, err)
			if tc.local == "" {
				assert.Nil(t, sp)
			} else if assert.NotNil(t, sp) {
				assert.Equal(t, tc.local, sp.local)
			}
			if tc.info != "" {
				assert.Equal(t, tc.info, string(textFile(c.info)))
			}
			if tc.gen != "" {
				want, err := os.ReadFile(tc.gen)
				require.NoError(t, err)
				got, err := goCode(prog, c, name, "dp")
				require.NoError(t, err)
				assert.Equal(t, string(want), string(got), "relay.gen.go is not current; run go generate")
			}
			if tc.ids != nil {
				got := map[string]uint32{c.keysName: c.keysID}
				for _, x := range c.info.GetTables() {
					got[x.GetPreamble().GetName()] = x.GetPreamble().GetId()
				}
				for _, x := range c.info.GetActions() {
					got[x.GetPreamble().GetName()] = x.GetPreamble().GetId()
				}
				for _, x := range c.info.GetCounters() {
					got[x.GetPreamble().GetName()] = x.GetPreamble().GetId()
				}
				for _, x := range c.info.GetMeters() {
					got[x.GetPreamble().GetName()] = x.GetPreamble().GetId()
				}
				for _, x := range c.info.GetControllerPacketMetadata() {
					got[x.GetPreamble().GetName()] = x.GetPreamble().GetId()
				}
				for n, id := range tc.ids {
					assert.Equal(t, id, got[n], n)
				}
			}
		})
	}
}

// baseProg is the program of the no split case. It declares R_X.
func baseProg(t *testing.T) string {
	t.Helper()
	return readCase(t, "testdata/cases/no-split.txtar").src
}

// TestConstValue checks the precedence and the widths of constant expressions.
func TestConstValue(t *testing.T) {
	cases := []struct {
		expr string
		want uint64
		ok   bool
	}{
		{"1 + 2 * 3", 7, true},
		{"(1 + 2) * 3", 9, true},
		{"1 << 2 + 1", 8, true},    // + binds tighter than <<.
		{"6 & 3 == 2", 1, true},    // & binds tighter than ==, as in p4c.
		{"1 | 2 ^ 3 & 1", 3, true}, // & before ^ before |.
		{"16 >> 2 >= 4", 1, true},  // The parser joins > > and > =.
		{"1 > 0 ? 5 : 1 > 2 ? 6 : 7", 5, true},
		{"0 > 1 ? 5 : 1 > 2 ? 6 : 7", 7, true},
		{"(bit<64>)(8w255 + 8w2)", 1, true}, // bit<8> wraps.
		{"(bit<4>)0x1f", 15, true},
		{"~8w0", 255, true},
		{"-8w1", 255, true},
		{"8w1 - 8w2", 255, true},
		{"!(1 == 1) || 2 != 2", 0, true},
		{"R_X + 1", 2, true},
		{"R_W", 4, true},                            // bit<8> wraps 8w250 + 8w10.
		{"(bit<8>)(1 - 2)", 255, true},              // An integer with no width can be negative.
		{"(bit<64>)((128w1 << 64) >> 64)", 1, true}, // bit<128> does not lose the high bits.
		{"1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1", 20, true},
		{"m.port", 0, false},
		{"E + 1", 0, false},             // A constant that refers to itself.
		{"(bit<64>)(1 << 64)", 0, true}, // A cast wraps.
	}
	base := baseProg(t)
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			consts := "const bit<8> R_X = 1;\nconst bit<8> R_W = 8w250 + 8w10;\nconst bit<64> E = " + tc.expr + ";"
			p, err := parse("t.p4", strings.Replace(base, "const bit<8> R_X = 1;", consts, 1))
			require.NoError(t, err)
			got, ok := p.constUint(&ident{name: "E"})
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestReasons checks that a drop reason has its bit<8> value.
func TestReasons(t *testing.T) {
	p, err := parse("t.p4", strings.Replace(baseProg(t), "const bit<8> R_X = 1;", "const bit<8> R_X = 1;\nconst bit<8> R_WRAP = 8w250 + 8w10;", 1))
	require.NoError(t, err)
	rs, err := (&gen{prog: p, srcName: "t.p4"}).reasons()
	require.NoError(t, err)
	assert.Equal(t, []reason{{name: "X", value: 1}, {name: "Wrap", value: 4}}, rs)
}
