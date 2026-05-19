package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"dagger/apoxy-cli/internal/dagger"
)

const (
	apoxyRepo       = "apoxy-dev/apoxy"
	apoxyCloudURL   = "https://github.com/apoxy-dev/apoxy-cloud.git"
	changelogPath   = "run/docs2/content/docs/changelog"
	indexFile       = "index.mdx"
	archiveFile     = "archive.mdx"
	maxIndexEntries = 10
	changelogModel  = "claude-sonnet-4-6"
)

// ghRelease mirrors the subset of the GitHub /releases/tags response we
// need. https://docs.github.com/en/rest/releases/releases
type ghRelease struct {
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	TagName     string    `json:"tag_name"`
}

// PublishApoxyCloudChangelog appends a new release entry to apoxy-cloud's
// docs2 changelog, trims the index to the most recent maxIndexEntries
// releases (older entries move to archive.mdx), and pushes the commit.
//
// The function runs a single Sonnet pass over the GitHub release body to
// reshape it into docs2 MDX style; it does not depend on the apoxy-cli
// source tree.
//
// When dryRun is true, the function skips the final `git push` and instead
// emits the staged diff to stdout — useful for verifying generated output
// against a real release without writing to apoxy-cloud/main.
func (m *ApoxyCli) PublishApoxyCloudChangelog(
	ctx context.Context,
	tag string,
	githubToken *dagger.Secret,
	apoxyCloudToken *dagger.Secret,
	// +optional
	dryRun bool,
) (*dagger.Container, error) {
	ghTokenPlain, err := githubToken.Plaintext(ctx)
	if err != nil {
		return nil, fmt.Errorf("read github token: %w", err)
	}

	rel, err := fetchGitHubRelease(ctx, apoxyRepo, tag, ghTokenPlain)
	if err != nil {
		return nil, fmt.Errorf("fetch release %s: %w", tag, err)
	}
	prevTag, err := previousGitHubTag(ctx, apoxyRepo, tag, ghTokenPlain)
	if err != nil {
		// Non-fatal — the body just won't get a Full Changelog footer.
		fmt.Printf("warning: previous tag lookup failed for %s: %v\n", tag, err)
		prevTag = ""
	}

	llmReply, err := dag.LLM(dagger.LLMOpts{Model: changelogModel}).
		WithPrompt(buildChangelogPrompt(tag, prevTag, rel.Body)).
		LastReply(ctx)
	if err != nil {
		return nil, fmt.Errorf("llm reformat: %w", err)
	}
	desc, body, ok := parseLLMChangelog(llmReply)
	if !ok {
		fmt.Println("warning: LLM output did not match expected format; falling back to raw GitHub release body")
		desc = firstParagraph(rel.Body)
		body = strings.TrimSpace(rel.Body)
		if prevTag != "" && !strings.Contains(body, "Full Changelog") {
			body += fmt.Sprintf(
				"\n\n**Full Changelog**: [%s...%s](https://github.com/%s/compare/%s...%s)",
				prevTag, tag, apoxyRepo, prevTag, tag,
			)
		}
	}
	if desc == "" {
		desc = "Released " + rel.PublishedAt.UTC().Format("Jan 2, 2006") + "."
	}

	// Pull the changelog directory out of apoxy-cloud@main via dag.Git so we
	// can read existing files (for order computation, index/archive merge)
	// without spinning up a container just to cat them.
	repo := dag.Git(apoxyCloudURL, dagger.GitOpts{
		HTTPAuthUsername: "x-access-token",
		HTTPAuthToken:    apoxyCloudToken,
	}).Branch("main").Tree()
	cdir := repo.Directory(changelogPath)

	slug := changelogSlug(tag)
	order, err := nextChangelogOrder(ctx, cdir, slug)
	if err != nil {
		return nil, fmt.Errorf("compute order: %w", err)
	}

	pub := rel.PublishedAt.UTC()
	dateStr := pub.Format("Jan 2, 2006")
	pageContent := renderChangelogPage(tag, desc, body, dateStr, order)

	indexContents, err := cdir.File(indexFile).Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", indexFile, err)
	}
	archiveContents, err := cdir.File(archiveFile).Contents(ctx)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", archiveFile, err)
	}

	newIndex := insertIndexEntry(indexContents, tag, slug, dateStr, desc, pub.Year())
	trimmedIndex, newArchive, archivedSlugs := trimIndexAndArchive(newIndex, archiveContents, dateStr)

	// Apply file changes on top of the cloned tree (.git included by
	// default — important; we push from it in the commit container).
	updated := repo.
		WithNewFile(changelogPath+"/"+slug+".mdx", pageContent).
		WithNewFile(changelogPath+"/"+indexFile, trimmedIndex).
		WithNewFile(changelogPath+"/"+archiveFile, newArchive)
	for _, s := range archivedSlugs {
		updated = updated.WithoutFile(changelogPath + "/" + s + ".mdx")
	}

	finalCmd := fmt.Sprintf(`
set -e
if git diff --cached --quiet; then
  echo "No changelog changes for %s; skipping commit."
  exit 0
fi
git commit -m "[docs2] add %s release notes"
git remote set-url origin "https://x-access-token:${APOXY_CLOUD_TOKEN}@github.com/apoxy-dev/apoxy-cloud.git"
git push origin HEAD:main
`, tag, tag)
	if dryRun {
		finalCmd = fmt.Sprintf(`
set -e
echo "=== DRY RUN for %s — staged changes (not pushed) ==="
git status --short %s
echo "=== diff ==="
git diff --cached -- %s
`, tag, changelogPath, changelogPath)
	}

	return dag.Container().
		From("alpine/git:latest").
		WithSecretVariable("APOXY_CLOUD_TOKEN", apoxyCloudToken).
		WithMountedDirectory("/repo", updated).
		WithWorkdir("/repo").
		WithExec([]string{"git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"}).
		WithExec([]string{"git", "config", "user.name", "github-actions[bot]"}).
		WithExec([]string{"git", "add", "-A", changelogPath}).
		WithExec([]string{"sh", "-c", finalCmd}), nil
}

// changelogSlug returns the per-release MDX filename stem for a tag.
func changelogSlug(tag string) string {
	return "apoxy-" + strings.ReplaceAll(tag, ".", "-")
}

// --- GitHub REST helpers -----------------------------------------------------

func githubGET(ctx context.Context, url, token string, into any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s: %s: %s", url, res.Status, b)
	}
	return json.NewDecoder(res.Body).Decode(into)
}

func fetchGitHubRelease(ctx context.Context, repo, tag, token string) (*ghRelease, error) {
	var rel ghRelease
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, tag)
	if err := githubGET(ctx, url, token, &rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// previousGitHubTag returns the tag of the release published immediately
// before `tag`, or "" if `tag` is the oldest known release.
func previousGitHubTag(ctx context.Context, repo, tag, token string) (string, error) {
	var rels []ghRelease
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=200", repo)
	if err := githubGET(ctx, url, token, &rels); err != nil {
		return "", err
	}
	sort.Slice(rels, func(i, j int) bool {
		return rels[i].PublishedAt.After(rels[j].PublishedAt)
	})
	for i, r := range rels {
		if r.TagName == tag && i+1 < len(rels) {
			return rels[i+1].TagName, nil
		}
	}
	return "", nil
}

// --- LLM prompt + parser -----------------------------------------------------

func buildChangelogPrompt(tag, prevTag, rawNotes string) string {
	full := ""
	if prevTag != "" {
		full = fmt.Sprintf(
			"\n\nEnd the body with this exact line (no surrounding blank lines beyond a single one above it):\n"+
				"**Full Changelog**: [%s...%s](https://github.com/%s/compare/%s...%s)",
			prevTag, tag, apoxyRepo, prevTag, tag,
		)
	}
	return fmt.Sprintf(`You are rewriting GitHub release notes for tag %s into a docs2 MDX changelog page.

Output EXACTLY two sections separated by the literal sentinel lines "===DESC===" and "===BODY===". No other text.

===DESC===
<One sentence, plain text, no markdown, no leading "This release", no trailing
period drama. ≤180 characters. Summarize the most important user-facing changes.>

===BODY===
<docs2 MDX body. Open with one or two sentences that mirror the description,
written as prose (no heading). Then group changes under these headings, in this
order, skipping any heading that would have no bullets:

## Features
## Bug Fixes
## Improvements
## Infrastructure

Each bullet must be on a single line in this exact shape:
- **Short title** ([abbrevhash](https://github.com/%s/commit/<hash>))

When multiple commits share a theme, group them as:
- **Short title** ([h1](https://github.com/%s/commit/<h1>), [h2](https://github.com/%s/commit/<h2>))

Use ONLY external https links. Do NOT write any link whose target starts with
"/" — internal MDX links are routed by the site's basename and must not appear
in changelog bodies.

Do NOT emit YAML front-matter, h1 headings, or commentary before/after the
sections.>%s

Raw GitHub release notes for %s follow between the BEGIN/END markers. Use them
as the source of truth for content; reshape into the structure above:

BEGIN RAW NOTES
%s
END RAW NOTES
`, tag, apoxyRepo, apoxyRepo, apoxyRepo, full, tag, rawNotes)
}

// parseLLMChangelog extracts the description and body sections from the
// model reply. Returns ok=false if the sentinels are missing.
func parseLLMChangelog(reply string) (desc, body string, ok bool) {
	const (
		descSep = "===DESC==="
		bodySep = "===BODY==="
	)
	di := strings.Index(reply, descSep)
	bi := strings.Index(reply, bodySep)
	if di < 0 || bi < 0 || bi < di {
		return "", "", false
	}
	desc = strings.TrimSpace(reply[di+len(descSep) : bi])
	body = strings.TrimSpace(reply[bi+len(bodySep):])
	// The description is supposed to be a single sentence; if the LLM
	// added a second line, drop it.
	if nl := strings.IndexByte(desc, '\n'); nl > 0 {
		desc = strings.TrimSpace(desc[:nl])
	}
	if desc == "" || body == "" {
		return "", "", false
	}
	return desc, body, true
}

// firstParagraph picks the first non-heading, non-bullet, non-link line of a
// markdown body. Used only as the fallback description when LLM parsing fails.
func firstParagraph(body string) string {
	for _, ln := range strings.Split(body, "\n") {
		s := strings.TrimSpace(ln)
		if s == "" {
			continue
		}
		switch s[0] {
		case '#', '*', '-', '{', '[':
			continue
		}
		if strings.HasPrefix(s, "**Full") {
			continue
		}
		return s
	}
	return ""
}

// --- Order computation -------------------------------------------------------

var orderRe = regexp.MustCompile(`(?m)^order:\s*(\d+)\s*$`)

// nextChangelogOrder returns the order: value to use for a new (or
// re-published) release page. Re-runs preserve the existing order so the
// page doesn't jump around in the sidebar. New releases get
// (current minimum order) - 1, so they sit at the top.
func nextChangelogOrder(ctx context.Context, cdir *dagger.Directory, slug string) (int, error) {
	existingPath := slug + ".mdx"
	if exists, _ := cdir.Exists(ctx, existingPath); exists {
		contents, err := cdir.File(existingPath).Contents(ctx)
		if err == nil {
			if m := orderRe.FindStringSubmatch(contents); m != nil {
				n, err := strconv.Atoi(m[1])
				if err == nil {
					return n, nil
				}
			}
		}
	}

	matches, err := cdir.Glob(ctx, "apoxy-*.mdx")
	if err != nil {
		return 0, err
	}
	lo := 200
	for _, p := range matches {
		c, err := cdir.File(p).Contents(ctx)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", p, err)
		}
		if m := orderRe.FindStringSubmatch(c); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n < lo {
				lo = n
			}
		}
	}
	return lo - 1, nil
}

// --- Page rendering ----------------------------------------------------------

func renderChangelogPage(tag, desc, body, date string, order int) string {
	return fmt.Sprintf(`---
title: "Apoxy %s"
navTitle: "%s"
description: "%s"
section: changelog
group: "Recent releases"
order: %d
eyebrow: Release
updated: "%s"
---

%s
`, tag, tag, yamlEsc(desc), order, date, strings.TrimSpace(body))
}

func yamlEsc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// --- Index manipulation ------------------------------------------------------

var (
	indexUpdatedRe     = regexp.MustCompile(`(?m)^updated:\s*".*"$`)
	indexYearRe        = regexp.MustCompile(`(?m)^## (\d{4})\n`)
	indexEntryHeaderRe = regexp.MustCompile(`(?m)^### \[Apoxy (v[\d.]+)\]\(/changelog/(apoxy-v[\d-]+)\) — (.+)$`)
)

// insertIndexEntry inserts (or refreshes) the entry for tag in index.mdx.
// Idempotent: if the slug is already present, returns the input unchanged.
func insertIndexEntry(index, tag, slug, date, desc string, year int) string {
	if strings.Contains(index, fmt.Sprintf("](/changelog/%s)", slug)) {
		return index
	}
	out := indexUpdatedRe.ReplaceAllString(index, fmt.Sprintf(`updated: "%s"`, date))
	entry := fmt.Sprintf("### [Apoxy %s](/changelog/%s) — %s\n\n%s\n\n", tag, slug, date, desc)
	marker := fmt.Sprintf("## %d\n\n", year)
	if strings.Contains(out, marker) {
		return strings.Replace(out, marker, marker+entry, 1)
	}
	section := fmt.Sprintf("## %d\n\n%s", year, entry)
	if loc := indexYearRe.FindStringIndex(out); loc != nil {
		return out[:loc[0]] + section + out[loc[0]:]
	}
	return strings.TrimRight(out, "\n") + "\n\n" + section
}

// indexEntry captures one parsed `### [Apoxy ...] — date\n\n<desc>\n\n` block.
type indexEntry struct {
	tag, slug, date, desc string
	start, end            int // byte offsets in the source string
}

// parseIndexEntries walks `### [Apoxy ...] — date` headings and pairs each
// with the following description paragraph. Entry byte ranges include the
// heading, the blank line after it, the description paragraph, and the
// trailing blank line — so that removing index[entry.start:entry.end]
// cleanly excises the block.
func parseIndexEntries(index string) []indexEntry {
	var entries []indexEntry
	// Iterate over each header position in the source.
	headers := indexEntryHeaderRe.FindAllStringSubmatchIndex(index, -1)
	if len(headers) == 0 {
		return nil
	}
	// To find where each entry's description ends, find the start of the
	// next entry — which is either the next `### ` header, the next `## `
	// year header, or EOF.
	nextDelim := func(after int) int {
		// Earliest index of "\n### " or "\n## " after `after`, or len(index).
		bound := len(index)
		if i := strings.Index(index[after:], "\n### "); i >= 0 {
			if cand := after + i + 1; cand < bound {
				bound = cand
			}
		}
		if i := strings.Index(index[after:], "\n## "); i >= 0 {
			if cand := after + i + 1; cand < bound {
				bound = cand
			}
		}
		return bound
	}
	for _, m := range headers {
		// m[0:1] is the header line bounds (excluding the trailing newline).
		headerStart := m[0]
		headerEnd := m[1] // points to the '\n' at the end of the header line
		tag := index[m[2]:m[3]]
		slug := index[m[4]:m[5]]
		date := strings.TrimSpace(index[m[6]:m[7]])

		// Description begins after the blank line that follows the header.
		// Defensive: if there's no blank line, treat the description as empty.
		descStart := headerEnd + 1 // skip header's '\n'
		// Skip a single blank line, if present.
		if strings.HasPrefix(index[descStart:], "\n") {
			descStart++
		}
		entryEnd := nextDelim(descStart)
		desc := strings.TrimSpace(index[descStart:entryEnd])

		entries = append(entries, indexEntry{
			tag:   tag,
			slug:  slug,
			date:  date,
			desc:  desc,
			start: headerStart,
			end:   entryEnd,
		})
	}
	return entries
}

// trimIndexAndArchive enforces the maxIndexEntries cap on index.mdx.
// Entries beyond the cap are removed from the index and inserted into
// archive.mdx in the condensed form already used by archive.mdx, and
// the corresponding per-release MDX file slugs are returned so the
// caller can WithoutFile() them. Idempotent: entries whose GitHub
// release URL is already in archive.mdx are not re-inserted.
func trimIndexAndArchive(index, archive, today string) (newIndex, newArchive string, archivedSlugs []string) {
	entries := parseIndexEntries(index)
	if len(entries) <= maxIndexEntries {
		return index, archive, nil
	}

	// Iterate from the tail (oldest) and pop until we're at the cap.
	overflow := entries[maxIndexEntries:]

	// Rebuild index without the overflow entries. Walk byte ranges in
	// reverse to keep offsets valid.
	newIndex = index
	for i := len(overflow) - 1; i >= 0; i-- {
		e := overflow[i]
		newIndex = newIndex[:e.start] + newIndex[e.end:]
	}
	// Drop any year-section headings that are now followed only by another
	// year heading (or EOF) with no entries between them.
	newIndex = stripEmptyYearSections(newIndex)
	// Bump `updated:` to today.
	newIndex = indexUpdatedRe.ReplaceAllString(newIndex, fmt.Sprintf(`updated: "%s"`, today))

	newArchive = archive
	for _, e := range overflow {
		tagURL := fmt.Sprintf("https://github.com/%s/releases/tag/%s", apoxyRepo, e.tag)
		if strings.Contains(newArchive, tagURL) {
			// Already archived. Still flag the per-release MDX for deletion
			// so cleanup happens on re-runs after a manual edit.
			archivedSlugs = append(archivedSlugs, e.slug)
			continue
		}
		year, err := parseEntryYear(e.date)
		if err != nil {
			fmt.Printf("warning: could not parse year from %q for %s, skipping archive: %v\n", e.date, e.tag, err)
			continue
		}
		newArchive = insertArchiveEntry(newArchive, e.tag, e.date, e.desc, year, tagURL)
		archivedSlugs = append(archivedSlugs, e.slug)
	}
	if len(archivedSlugs) > 0 {
		newArchive = indexUpdatedRe.ReplaceAllString(newArchive, fmt.Sprintf(`updated: "%s"`, today))
	}
	return newIndex, newArchive, archivedSlugs
}

// stripEmptyYearSections removes any `## YYYY\n\n` heading that has no
// `### ` entries underneath before the next `## ` heading or EOF.
func stripEmptyYearSections(index string) string {
	locs := indexYearRe.FindAllStringIndex(index, -1)
	if len(locs) == 0 {
		return index
	}
	// Walk in reverse so removals don't shift earlier offsets.
	for i := len(locs) - 1; i >= 0; i-- {
		start := locs[i][0]
		var end int
		if i+1 < len(locs) {
			end = locs[i+1][0]
		} else {
			end = len(index)
		}
		section := index[start:end]
		if !strings.Contains(section, "### ") {
			index = index[:start] + index[end:]
		}
	}
	return index
}

// insertArchiveEntry adds a condensed entry to archive.mdx under the
// matching `## YEAR` heading, creating the year section above the next
// newer one if it doesn't exist.
func insertArchiveEntry(archive, tag, date, desc string, year int, tagURL string) string {
	entry := fmt.Sprintf("### Apoxy %s — %s\n\n%s\n\n[GitHub release ↗](%s)\n\n", tag, date, desc, tagURL)
	marker := fmt.Sprintf("## %d\n\n", year)
	if strings.Contains(archive, marker) {
		return strings.Replace(archive, marker, marker+entry, 1)
	}
	section := fmt.Sprintf("## %d\n\n%s", year, entry)
	if loc := indexYearRe.FindStringIndex(archive); loc != nil {
		return archive[:loc[0]] + section + archive[loc[0]:]
	}
	return strings.TrimRight(archive, "\n") + "\n\n" + section
}

// parseEntryYear extracts the year from a "Jan 2, 2006"-style date string.
func parseEntryYear(date string) (int, error) {
	t, err := time.Parse("Jan 2, 2006", strings.TrimSpace(date))
	if err != nil {
		return 0, err
	}
	return t.Year(), nil
}
