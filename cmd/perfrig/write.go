package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// writeCmd is the hidden "perfrig write PATTERN VALUE" command. It writes VALUE
// to each file that PATTERN matches. With no match, it exits with code 3.
func writeCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: perfrig write PATTERN VALUE")
	}
	paths, err := filepath.Glob(args[0])
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("%w: no file matches %s", errInfra, args[0])
	}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte(args[1]+"\n"), 0); err != nil {
			return err
		}
	}
	return nil
}

// writeIn runs "perfrig write" in the netns ns, which sees the /proc/sys and
// /sys files of that netns.
func writeIn(ctx context.Context, ns, pattern, value string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	_, err = command(ctx, "ip", "netns", "exec", ns, self, "write", pattern, value)
	return err
}
