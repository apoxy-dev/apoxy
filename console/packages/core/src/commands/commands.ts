// Command model + registry-fed command generation (APO-781). The palette is fed
// by the registry: every served kind becomes a "Go to <kind>" command, and apps
// can append their own. Filtering/ranking is a pure function so it is tested
// without rendering. Navigation is injected (no router dependency in core).

import type { ReactNode } from 'react'
import type { GVR } from '../lib/k8s-types'
import type { Registry } from '../registry/types'

/** One palette command. `run` performs the action; `keywords` widen matching. */
export interface Command {
  /** Stable id (React key, also dedupe key). */
  id: string
  /** Primary label shown in the palette. */
  title: string
  /** Secondary line (e.g. the GVR, or a hint). */
  subtitle?: string
  /** Section label the palette groups under. */
  group?: string
  /** Extra terms matched in addition to the title. */
  keywords?: string[]
  icon?: ReactNode
  run: () => void
}

export interface BuildResourceCommandsOptions {
  /** Navigate to a URL (the app supplies its router's navigate). */
  navigate: (to: string) => void
  /** Hide commands for GVRs the apiserver doesn't serve. Defaults to all served. */
  isServed?: (gvr: GVR) => boolean
  /** Group label for the generated navigation commands. Defaults to `Go to`. */
  group?: string
}

/**
 * One navigation command per registry entry (gated by discovery, like the
 * sidebar). Adding a kind to the registry adds it to the palette for free.
 */
export function buildResourceCommands(registry: Registry, opts: BuildResourceCommandsOptions): Command[] {
  const isServed = opts.isServed ?? (() => true)
  const group = opts.group ?? 'Go to'
  return registry
    .all()
    .filter((e) => e.requires.every(isServed))
    .map((e) => ({
      id: `nav:${e.path}`,
      title: e.displayName,
      subtitle: `${e.gvr.group || 'core'}/${e.gvr.version}`,
      group,
      keywords: [e.kind, e.gvr.resource, e.gvr.group].filter(Boolean),
      icon: e.icon,
      run: () => opts.navigate(`/${e.path}`),
    }))
}

/** A command plus its computed relevance, for ranked display. */
export interface ScoredCommand {
  command: Command
  score: number
}

/**
 * Rank a command against a lowercased query. Higher is better; `0` means no
 * match. Title hits outrank keyword/subtitle hits, and an earlier match position
 * outranks a later one, so the most obvious command floats to the top.
 */
export function scoreCommand(command: Command, q: string): number {
  if (!q) return 1
  const title = command.title.toLowerCase()
  if (title === q) return 1000
  if (title.startsWith(q)) return 800 - title.indexOf(q)
  const ti = title.indexOf(q)
  if (ti >= 0) return 600 - ti
  for (const kw of command.keywords ?? []) {
    const k = kw.toLowerCase()
    if (k.startsWith(q)) return 400
    if (k.includes(q)) return 300
  }
  if ((command.subtitle ?? '').toLowerCase().includes(q)) return 200
  // Subsequence (fuzzy) match as a last resort: `gw` matches `gateway`.
  if (isSubsequence(q, title)) return 100
  return 0
}

/** True when every char of `q` appears in `s` in order (a fuzzy match). */
export function isSubsequence(q: string, s: string): boolean {
  let i = 0
  for (let j = 0; j < s.length && i < q.length; j++) {
    if (s[j] === q[i]) i++
  }
  return i === q.length
}

/**
 * Filter + rank commands for a query. Ties keep the input (registration) order,
 * so a blank query returns the commands unchanged.
 */
export function filterCommands(commands: Command[], query: string): Command[] {
  const q = query.trim().toLowerCase()
  if (!q) return commands
  const scored: Array<ScoredCommand & { order: number }> = []
  commands.forEach((command, order) => {
    const score = scoreCommand(command, q)
    if (score > 0) scored.push({ command, score, order })
  })
  scored.sort((a, b) => b.score - a.score || a.order - b.order)
  return scored.map((s) => s.command)
}
