// SPDX-License-Identifier: AGPL-3.0-only

// Command p4gen reads relay.p4, a P4 program of the subset of the relay engine design, and
// writes its P4Info in the text layout of p4test and the Go code of the pipeline: the IDs, entry
// types, drop reasons and PspSa instance, and the parse and apply code (pipe.go). It has its own
// parser and does not use p4c; CI runs p4test as the type check and compares the two P4Info files
// with diff.
package main

import (
	"flag"
	"fmt"
	"go/format"
	"log/slog"
	"os"
)

func main() {
	srcPath := flag.String("p4", "relay.p4", "P4 source")
	infoPath := flag.String("p4info", "relay.p4info.txtpb", "P4Info text file to write")
	out := flag.String("out", "relay.gen.go", "Go file to write")
	pkg := flag.String("package", "dp", "Go package name")
	flag.Parse()
	if err := run(*srcPath, *infoPath, *out, *pkg); err != nil {
		slog.Error("Failed to make the P4Info and the Go code of the P4 program", "error", err)
		os.Exit(1)
	}
}

func run(srcPath, infoPath, out, pkg string) error {
	src, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	prog, c, err := load(srcPath, string(src))
	if err != nil {
		return err
	}
	code, err := goCode(prog, c, srcPath, pkg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(infoPath, textFile(c.info), 0o644); err != nil {
		return err
	}
	return os.WriteFile(out, code, 0o644)
}

// goCode returns the formatted Go code of prog.
func goCode(prog *program, c *compiled, srcName, pkg string) ([]byte, error) {
	code, err := (&gen{prog: prog, info: c.info, c: c, srcName: srcName}).render(pkg)
	if err != nil {
		return nil, err
	}
	formatted, err := format.Source(code)
	if err != nil {
		return nil, fmt.Errorf("failed to format the output: %w\n%s", err, code)
	}
	return formatted, nil
}

// load parses src, checks the split and makes the P4Info.
func load(file, src string) (*program, *compiled, error) {
	prog, err := parse(file, src)
	if err != nil {
		return nil, nil, err
	}
	if _, err := split(file, prog); err != nil {
		return nil, nil, err
	}
	c, err := compile(file, prog)
	if err != nil {
		return nil, nil, err
	}
	return prog, c, nil
}
