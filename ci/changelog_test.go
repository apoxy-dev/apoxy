package main

import (
	"strings"
	"testing"
)

func TestParseLLMChangelog(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantDesc string
		wantBody string
		wantOk   bool
	}{
		{
			name: "happy path",
			input: `===DESC===
Adds cert management to k8s subcommands and improves local dev workflows.

===BODY===
This release adds certificate management capabilities.

## Features

- **Cert mgmt** ([abc1234](https://github.com/apoxy-dev/apoxy/commit/abc1234))

**Full Changelog**: [v0.19.3...v0.20.0](https://github.com/apoxy-dev/apoxy/compare/v0.19.3...v0.20.0)
`,
			wantDesc: "Adds cert management to k8s subcommands and improves local dev workflows.",
			wantBody: "This release adds certificate management capabilities.\n\n## Features\n\n- **Cert mgmt** ([abc1234](https://github.com/apoxy-dev/apoxy/commit/abc1234))\n\n**Full Changelog**: [v0.19.3...v0.20.0](https://github.com/apoxy-dev/apoxy/compare/v0.19.3...v0.20.0)",
			wantOk:   true,
		},
		{
			name: "desc with chatty trailing line is trimmed",
			input: `===DESC===
Real description on one line.
This second line should be discarded.

===BODY===
Body content.
`,
			wantDesc: "Real description on one line.",
			wantBody: "Body content.",
			wantOk:   true,
		},
		{
			name:    "missing sentinels",
			input:   "Just some text with no sentinels at all.",
			wantOk:  false,
		},
		{
			name: "sentinels in wrong order",
			input: `===BODY===
Body comes first.
===DESC===
Desc comes second.
`,
			wantOk: false,
		},
		{
			name: "empty body section",
			input: `===DESC===
Desc only.

===BODY===
`,
			wantOk: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			desc, body, ok := parseLLMChangelog(tc.input)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v (desc=%q body=%q)", ok, tc.wantOk, desc, body)
			}
			if !tc.wantOk {
				return
			}
			if desc != tc.wantDesc {
				t.Errorf("desc = %q, want %q", desc, tc.wantDesc)
			}
			if body != tc.wantBody {
				t.Errorf("body = %q, want %q", body, tc.wantBody)
			}
		})
	}
}

func TestParseIndexEntries(t *testing.T) {
	index := `---
title: "Changelog."
order: 1
updated: "May 13, 2026"
---

Intro paragraph.

## 2026

### [Apoxy v0.20.0](/changelog/apoxy-v0-20-0) — May 13, 2026

First release description.

### [Apoxy v0.19.3](/changelog/apoxy-v0-19-3) — May 9, 2026

Second release description.

## 2025

### [Apoxy v0.13.0](/changelog/apoxy-v0-13-0) — Nov 18, 2025

Older release description.
`
	got := parseIndexEntries(index)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	want := []indexEntry{
		{tag: "v0.20.0", slug: "apoxy-v0-20-0", date: "May 13, 2026", desc: "First release description."},
		{tag: "v0.19.3", slug: "apoxy-v0-19-3", date: "May 9, 2026", desc: "Second release description."},
		{tag: "v0.13.0", slug: "apoxy-v0-13-0", date: "Nov 18, 2025", desc: "Older release description."},
	}
	for i, w := range want {
		if got[i].tag != w.tag || got[i].slug != w.slug || got[i].date != w.date || got[i].desc != w.desc {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestInsertIndexEntry(t *testing.T) {
	base := `---
title: "Changelog."
updated: "May 9, 2026"
---

Intro.

## 2026

### [Apoxy v0.19.3](/changelog/apoxy-v0-19-3) — May 9, 2026

Older.

## 2025

### [Apoxy v0.13.0](/changelog/apoxy-v0-13-0) — Nov 18, 2025

Way older.
`

	t.Run("inserts under existing year header at top", func(t *testing.T) {
		got := insertIndexEntry(base, "v0.20.0", "apoxy-v0-20-0", "May 13, 2026", "New release.", 2026)
		if !strings.Contains(got, "### [Apoxy v0.20.0](/changelog/apoxy-v0-20-0) — May 13, 2026\n\nNew release.") {
			t.Errorf("new entry missing or malformed: %q", got)
		}
		// New entry must precede the v0.19.3 entry.
		if idxNew := strings.Index(got, "v0.20.0"); idxNew >= strings.Index(got, "v0.19.3") {
			t.Errorf("new entry not inserted above existing entries")
		}
		if !strings.Contains(got, `updated: "May 13, 2026"`) {
			t.Errorf("updated frontmatter not bumped: %q", got)
		}
	})

	t.Run("idempotent on re-insert", func(t *testing.T) {
		once := insertIndexEntry(base, "v0.20.0", "apoxy-v0-20-0", "May 13, 2026", "New release.", 2026)
		twice := insertIndexEntry(once, "v0.20.0", "apoxy-v0-20-0", "May 13, 2026", "New release.", 2026)
		if once != twice {
			t.Errorf("second insert changed the index — not idempotent")
		}
	})

	t.Run("creates new year section above older one", func(t *testing.T) {
		baseOnly2025 := `---
title: "Changelog."
updated: "Nov 18, 2025"
---

Intro.

## 2025

### [Apoxy v0.13.0](/changelog/apoxy-v0-13-0) — Nov 18, 2025

Older.
`
		got := insertIndexEntry(baseOnly2025, "v0.14.0", "apoxy-v0-14-0", "Jan 21, 2026", "New year.", 2026)
		if !strings.Contains(got, "## 2026\n\n### [Apoxy v0.14.0]") {
			t.Errorf("expected new ## 2026 section with entry, got %q", got)
		}
		if strings.Index(got, "## 2026") >= strings.Index(got, "## 2025") {
			t.Errorf("## 2026 must come before ## 2025")
		}
	})
}

func TestTrimIndexAndArchive(t *testing.T) {
	// Build an index with exactly 12 entries so trim must pop 2.
	var b strings.Builder
	b.WriteString(`---
title: "Changelog."
updated: "May 13, 2026"
---

Intro.

## 2026

`)
	for i := 0; i < 12; i++ {
		// Higher-numbered tags appear higher (newer).
		tag := newTagAt(20 - i)
		slug := "apoxy-" + strings.ReplaceAll(tag, ".", "-")
		date := nthDateIn2026(i)
		fmt := "### [Apoxy " + tag + "](/changelog/" + slug + ") — " + date + "\n\n" +
			"Description for " + tag + ".\n\n"
		b.WriteString(fmt)
	}
	index := b.String()

	archive := `---
title: "Changelog archive"
updated: "Apr 30, 2025"
---

Pre-existing intro.

## 2025

### Apoxy v0.9.3 — Apr 30, 2025

A pre-existing archive entry.

[GitHub release ↗](https://github.com/apoxy-dev/apoxy/releases/tag/v0.9.3)

`

	newIndex, newArchive, archivedSlugs := trimIndexAndArchive(index, archive, "May 20, 2026")

	// Index should have exactly 10 entries now.
	entries := parseIndexEntries(newIndex)
	if len(entries) != 10 {
		t.Fatalf("after trim, index has %d entries, want 10", len(entries))
	}

	// The two oldest tags (v0.9.X equivalents — last two of the original 12) should be archived.
	if len(archivedSlugs) != 2 {
		t.Fatalf("got %d archived slugs, want 2: %v", len(archivedSlugs), archivedSlugs)
	}
	for _, s := range archivedSlugs {
		if !strings.HasPrefix(s, "apoxy-") {
			t.Errorf("archived slug %q does not look right", s)
		}
		// And the archive should contain the GitHub release link.
		tag := strings.TrimPrefix(strings.ReplaceAll(s, "-", "."), "apoxy.")
		url := "https://github.com/apoxy-dev/apoxy/releases/tag/" + tag
		if !strings.Contains(newArchive, url) {
			t.Errorf("archive missing entry for %s; expected URL %q", tag, url)
		}
	}

	// Index `updated:` must be bumped to today.
	if !strings.Contains(newIndex, `updated: "May 20, 2026"`) {
		t.Errorf("index `updated:` was not bumped to today")
	}

	// Archive `updated:` must be bumped to today (entries were added).
	if !strings.Contains(newArchive, `updated: "May 20, 2026"`) {
		t.Errorf("archive `updated:` was not bumped to today")
	}

	// Pre-existing archive entry must still be there.
	if !strings.Contains(newArchive, "### Apoxy v0.9.3 — Apr 30, 2025") {
		t.Errorf("pre-existing archive entry was lost")
	}
}

func TestTrimIndexAndArchive_NoOp(t *testing.T) {
	index := `---
title: "Changelog."
updated: "May 13, 2026"
---

## 2026

### [Apoxy v0.20.0](/changelog/apoxy-v0-20-0) — May 13, 2026

Desc.
`
	archive := `---
title: "Archive"
updated: "Apr 30, 2025"
---
`
	newIndex, newArchive, slugs := trimIndexAndArchive(index, archive, "May 20, 2026")
	if newIndex != index {
		t.Errorf("index changed when below cap")
	}
	if newArchive != archive {
		t.Errorf("archive changed when below cap")
	}
	if len(slugs) != 0 {
		t.Errorf("got slugs %v, want none", slugs)
	}
}

func TestTrimIndexAndArchive_IdempotentArchive(t *testing.T) {
	// 11 entries → one needs to move. Re-running should not duplicate it.
	var b strings.Builder
	b.WriteString(`---
title: "Changelog."
updated: "May 13, 2026"
---

## 2026

`)
	for i := 0; i < 11; i++ {
		tag := newTagAt(20 - i)
		slug := "apoxy-" + strings.ReplaceAll(tag, ".", "-")
		date := nthDateIn2026(i)
		b.WriteString("### [Apoxy " + tag + "](/changelog/" + slug + ") — " + date + "\n\n" +
			"Desc for " + tag + ".\n\n")
	}
	index := b.String()
	archive := `---
title: "Archive"
updated: "Apr 30, 2025"
---
`

	once, archive1, slugs1 := trimIndexAndArchive(index, archive, "May 20, 2026")
	if len(slugs1) != 1 {
		t.Fatalf("first run: got %d slugs, want 1", len(slugs1))
	}

	// Second run on the trimmed index — should be a no-op.
	twice, archive2, slugs2 := trimIndexAndArchive(once, archive1, "May 21, 2026")
	if twice != once {
		t.Errorf("second-run index differs from first-run output")
	}
	if archive2 != archive1 {
		t.Errorf("second-run archive differs from first-run output")
	}
	if len(slugs2) != 0 {
		t.Errorf("second run produced slugs %v, want none", slugs2)
	}
}

func TestStripEmptyYearSections(t *testing.T) {
	index := `---
title: "x"
---

## 2026

## 2025

### [Apoxy v0.13.0](/changelog/apoxy-v0-13-0) — Nov 18, 2025

Desc.
`
	got := stripEmptyYearSections(index)
	if strings.Contains(got, "## 2026") {
		t.Errorf("empty ## 2026 section should have been removed: %q", got)
	}
	if !strings.Contains(got, "## 2025") {
		t.Errorf("non-empty ## 2025 section should be preserved")
	}
}

// --- helpers ---

func newTagAt(n int) string {
	// produces v0.<n>.0 — n is allowed to go negative, returns vN-like
	if n >= 0 {
		return "v0." + itoa(n) + ".0"
	}
	return "v0.0." + itoa(-n)
}

func nthDateIn2026(n int) string {
	months := []string{"May", "Apr", "Mar", "Feb", "Jan"}
	month := months[n%len(months)]
	day := (n%27 + 1)
	return month + " " + itoa(day) + ", 2026"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
