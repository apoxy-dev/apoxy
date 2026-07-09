// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

// scanOrphanIDs derives the sandbox ids present in a runsc --root dir from
// BOTH on-disk layouts: per-container directories AND the flat metadata files
// newer runsc writes directly into the root ("<id>_sandbox:<sid>.state" and
// ".lock"). A boot-time cleanup that only scans directories misses the flat
// layout entirely, leaving `runsc create` permanently failing with "container
// already exists" after any unclean restart. Portable and pure so it is
// testable off linux.
func scanOrphanIDs(stateDir string) ([]SandboxID, error) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return nil, err
	}
	seen := make(map[SandboxID]struct{})
	var ids []SandboxID
	add := func(id SandboxID) {
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir():
			add(SandboxID(name))
		case strings.Contains(name, "_sandbox:"):
			add(SandboxID(name[:strings.Index(name, "_sandbox:")]))
		}
	}
	return ids, nil
}

// removeSandboxMetaFiles removes the flat runsc metadata files for id from
// the root dir — the teardown counterpart of the flat layout scanOrphanIDs
// detects. Best-effort: runsc delete normally removes these itself; this
// catches the case where the delete failed or never ran.
func removeSandboxMetaFiles(stateDir string, id SandboxID) {
	matches, err := filepath.Glob(filepath.Join(stateDir, string(id)+"_sandbox:*"))
	if err != nil {
		return
	}
	for _, f := range matches {
		_ = os.Remove(f)
	}
}
