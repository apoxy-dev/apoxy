// A generic, data-driven Miller-column browser (APO-780/APO-782): N panes laid
// out left→right, where the selection in each pane narrows the rows shown in the
// next — the classic master→detail drill-down. For an apoxy Gateway it reads
// Listeners → Routes → Rules → Targets; the very same component backs clrk's
// EgressGateway browser by supplying a different `getItems`. So it is kept
// strictly kind-agnostic: the consumer owns the data (`getItems` returns the rows
// of a column given the selections to its left, plus the filter query), and this
// component owns selection, keyboard navigation (←/→ across columns, ↑/↓ within
// one, on the shared `moveMiller` cursor), the optional filter box, and the
// design's column chrome. It is purely presentational — no API types leak in —
// which is what makes it reusable.

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { cn } from "../../lib/cn";
import { moveMiller, type MillerCursor } from "../../keyboard/selection";

/** Pip color for a row's health: ok→leaf, warn→amber, err→coral. */
export type MillerStatus = "ok" | "warn" | "err";

export interface MillerItem {
  /** Stable id, unique within its column. Drives selection and the next column. */
  id: string;
  /** Primary line. */
  name: ReactNode;
  /** Render the primary line in the mono face (hostnames, match values). */
  mono?: boolean;
  /** Secondary line (tags, counts). */
  sub?: ReactNode;
  /** Leading status pip; omit for none. */
  status?: MillerStatus;
  /** Optional weight/utilization bar under the row (e.g. a backend traffic split);
   *  `value` is a percentage, `canary` tints it for a small-share lane. */
  meter?: { value: number; canary?: boolean };
  /** Optional per-row edit affordance (the hover pencil). */
  onEdit?: () => void;
}

export interface MillerColumnDef {
  id: string;
  /** Uppercase column header (e.g. "Listeners"). */
  label: string;
  /** Head "+" action; columns without it show no add button. */
  onAdd?: () => void;
  addTitle?: string;
  /** Disable the head "+" (e.g. nothing is selected to add under yet). */
  addDisabled?: boolean;
  /** Shown, centered, when the column has no rows. */
  emptyMessage?: ReactNode;
  /** Optional content pinned below the column's rows, given the resolved
   *  selection — e.g. an "apparent path" summary under a Targets column. */
  footer?: (selected: (string | null)[]) => ReactNode;
}

export interface MillerBrowserProps {
  columns: MillerColumnDef[];
  /**
   * Rows of column `col`, given the resolved selected id of every column to its
   * left (`selected[0..col-1]`) and the current filter `query` (empty string
   * when no search box is shown). Must be pure; memoize it (useCallback) so the
   * browser recomputes only when its real inputs change.
   */
  getItems: (col: number, selected: (string | null)[], query: string) => MillerItem[];
  /** CSS grid-template-columns for the panes; defaults to equal weights. */
  template?: string;
  /** Min height of the frame in px (the design uses 660). */
  minHeight?: number;
  ariaLabel?: string;
  /** Notified with the resolved selection whenever it changes. */
  onSelectionChange?: (selected: (string | null)[]) => void;
  /** When set, a filter box is shown above the columns; its text is passed as the
   *  third arg to getItems so the consumer decides what to match. `/` focuses it. */
  searchPlaceholder?: string;
}

const PIP: Record<MillerStatus, string> = {
  ok: "bg-[var(--apx-leaf)]",
  warn: "bg-[var(--apx-amber)]",
  err: "bg-[var(--apx-coral)]",
};

export function MillerBrowser({
  columns,
  getItems,
  template,
  minHeight = 660,
  ariaLabel = "Miller columns",
  onSelectionChange,
  searchPlaceholder,
}: MillerBrowserProps) {
  // Explicit user picks (nullable). The resolved selection below fills nulls and
  // now-invalid ids by auto-selecting each column's first row, cascading L→R.
  const [picks, setPicks] = useState<(string | null)[]>(() =>
    columns.map(() => null),
  );
  const [activeCol, setActiveCol] = useState(0);
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  // Resolve items + selection together in one left→right pass: each column's
  // rows depend on the resolved selection to its left (and the filter query), and
  // a pick that no longer exists (parent changed, or filtered out) falls back to
  // that column's first row.
  const { itemsByCol, selected } = useMemo(() => {
    const itemsByCol: MillerItem[][] = [];
    const selected: (string | null)[] = [];
    for (let c = 0; c < columns.length; c++) {
      const items = getItems(c, selected, query);
      const pick = picks[c] ?? null;
      const resolved =
        pick !== null && items.some((i) => i.id === pick)
          ? pick
          : (items[0]?.id ?? null);
      itemsByCol.push(items);
      selected.push(resolved);
    }
    return { itemsByCol, selected };
  }, [columns, getItems, picks, query]);

  const selKey = selected.join(" ");
  useEffect(() => {
    onSelectionChange?.(selected);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fire on resolved change only
  }, [selKey]);

  // Press "/" (when not already typing somewhere) to jump to the filter box, the
  // design's documented shortcut. Only wired when the box is shown.
  useEffect(() => {
    if (searchPlaceholder == null) return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || el?.isContentEditable) return;
      e.preventDefault();
      searchRef.current?.focus();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [searchPlaceholder]);

  // Pick row `id` in column `col`: keep the upstream picks, drop everything
  // downstream so the memo re-resolves the right-hand columns to their first
  // rows. The functional updater reads the *previous* picks (not a value captured
  // at render), so a burst of pick() calls within one event composes correctly.
  const pick = useCallback((col: number, id: string) => {
    setActiveCol(col);
    setPicks((prev) => {
      const next = prev.slice(0, col);
      next[col] = id;
      return next;
    });
  }, []);

  // onKeyDown is created once but reads the live derived state through this ref,
  // so a move that changes the selection without changing the active column still
  // sees fresh items/counts on the next keystroke.
  const live = useRef({ itemsByCol, selected, activeCol });
  live.current = { itemsByCol, selected, activeCol };

  const onKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      const { itemsByCol, selected, activeCol } = live.current;
      const counts = itemsByCol.map((c) => c.length);
      if (counts.length === 0) return;
      // Clamp in case a columns change left the active column past the end
      // (a consumer like clrk may grow/shrink its panes at runtime).
      const col = Math.min(activeCol, counts.length - 1);
      const cursor: MillerCursor = {
        col,
        row: itemsByCol[col]?.findIndex((it) => it.id === selected[col]) ?? -1,
      };
      switch (e.key) {
        case "ArrowDown":
        case "ArrowUp": {
          e.preventDefault();
          const next = moveMiller(
            cursor,
            0,
            e.key === "ArrowDown" ? 1 : -1,
            counts,
          );
          const it = itemsByCol[next.col]?.[next.row];
          if (it) pick(next.col, it.id);
          break;
        }
        case "ArrowRight":
        case "ArrowLeft": {
          e.preventDefault();
          setActiveCol(
            moveMiller(cursor, e.key === "ArrowRight" ? 1 : -1, 0, counts).col,
          );
          break;
        }
      }
    },
    [pick],
  );

  const grid = template ?? columns.map(() => "1fr").join(" ");

  const gridEl = (
    <div
      role="grid"
      aria-label={ariaLabel}
      tabIndex={0}
      onKeyDown={onKeyDown}
      className="grid rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)] outline-none focus-visible:shadow-[var(--sh-focus)]"
      style={{ gridTemplateColumns: grid, minHeight }}
    >
      {columns.map((col, c) => (
        <MillerCol
          key={col.id}
          def={col}
          items={itemsByCol[c] ?? []}
          selectedId={selected[c] ?? null}
          footer={col.footer ? col.footer(selected) : null}
          active={c === activeCol}
          last={c === columns.length - 1}
          onPick={(id) => pick(c, id)}
        />
      ))}
    </div>
  );

  if (searchPlaceholder == null) return gridEl;

  return (
    <div className="flex flex-col">
      <div className="mb-[16px] flex items-center justify-between gap-[16px]">
        <label className="flex max-w-[420px] flex-1 items-center gap-[8px] rounded-none border border-[color:var(--border-default)] bg-[var(--apx-white)] px-[12px] py-[8px]">
          <svg
            width="14"
            height="14"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            className="flex-none opacity-50"
            aria-hidden="true"
          >
            <circle cx="7" cy="7" r="4.5" />
            <path d="M11 11l3.5 3.5" />
          </svg>
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={searchPlaceholder}
            className="min-w-0 flex-1 border-0 bg-transparent text-[length:var(--t-body-sm)] text-[color:var(--text-primary)] outline-none placeholder:text-[color:var(--text-muted)]"
          />
          <kbd className="flex-none font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
            /
          </kbd>
        </label>
      </div>
      {gridEl}
    </div>
  );
}

function MillerCol({
  def,
  items,
  selectedId,
  footer,
  active,
  last,
  onPick,
}: {
  def: MillerColumnDef;
  items: MillerItem[];
  selectedId: string | null;
  footer?: ReactNode;
  active: boolean;
  last: boolean;
  onPick: (id: string) => void;
}) {
  return (
    <div
      role="rowgroup"
      aria-label={def.label}
      className={cn(
        "flex min-h-0 min-w-0 flex-col",
        !last && "border-r border-[color:var(--border-default)]",
      )}
    >
      <div className="flex items-center justify-between border-b border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[14px] py-[8px]">
        <span className="text-[length:var(--t-overline)] font-medium uppercase tracking-[0.14em] text-[color:var(--text-muted)]">
          {def.label}
        </span>
        <span className="flex items-center gap-[8px]">
          <span className="font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
            {items.length}
          </span>
          {def.onAdd && (
            <button
              type="button"
              title={def.addTitle ?? "Add"}
              disabled={def.addDisabled}
              onClick={def.onAdd}
              className="flex h-[22px] w-[22px] flex-none items-center justify-center rounded-none border border-[color:var(--apx-ink)] bg-[var(--apx-white)] text-[color:var(--apx-ink)] transition-colors hover:bg-[var(--apx-ink)] hover:text-[color:var(--apx-bone)] disabled:pointer-events-none disabled:opacity-40"
            >
              <svg
                width="11"
                height="11"
                viewBox="0 0 12 12"
                aria-hidden="true"
              >
                <path
                  d="M6 1v10M1 6h10"
                  stroke="currentColor"
                  strokeWidth="1.5"
                />
              </svg>
            </button>
          )}
        </span>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {items.length === 0 && footer == null ? (
          <div className="px-[16px] py-[24px] text-center font-mono text-[length:var(--t-body-sm)] text-[color:var(--text-disabled)]">
            {def.emptyMessage ?? "—"}
          </div>
        ) : (
          <>
            {items.map((it) => (
              <MillerRow
                key={it.id}
                item={it}
                selected={it.id === selectedId}
                active={active}
                onPick={() => onPick(it.id)}
              />
            ))}
            {footer}
          </>
        )}
      </div>
    </div>
  );
}

function MillerRow({
  item,
  selected,
  active,
  onPick,
}: {
  item: MillerItem;
  selected: boolean;
  active: boolean;
  onPick: () => void;
}) {
  return (
    <div
      role="row"
      aria-selected={selected}
      onClick={onPick}
      className={cn(
        "group flex min-h-[76px] cursor-pointer items-center gap-[10px] border-b border-l-2 border-b-[color:var(--border-subtle)] px-[14px] py-[11px]",
        selected
          ? "border-l-[color:var(--apx-ink)] bg-[var(--apx-mist)]"
          : "border-l-transparent hover:bg-[var(--apx-bone)]",
        selected && active && "shadow-[inset_0_0_0_1px_var(--apx-fog)]",
      )}
    >
      {item.status && (
        <span
          className={cn(
            "h-[6px] w-[6px] flex-none rounded-none",
            PIP[item.status],
          )}
          aria-hidden="true"
        />
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-[6px]">
        <div
          className={cn(
            "overflow-hidden text-ellipsis whitespace-nowrap text-[length:var(--t-body-sm)] font-medium text-[color:var(--text-primary)]",
            item.mono && "font-mono",
          )}
        >
          {item.name}
        </div>
        {item.sub != null && (
          <div className="flex flex-wrap items-center gap-[6px] font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
            {item.sub}
          </div>
        )}
        {item.meter && (
          <div className="mt-[2px] flex items-center gap-[8px]">
            <div className="h-[4px] flex-1 bg-[var(--apx-mist)]">
              <div
                className={cn(
                  "h-full",
                  item.meter.canary
                    ? "bg-[var(--apx-blue)]"
                    : "bg-[var(--apx-ink)]",
                )}
                style={{
                  width: `${Math.max(0, Math.min(100, item.meter.value))}%`,
                }}
              />
            </div>
            <span className="flex-none font-mono text-[length:var(--t-micro)] text-[color:var(--text-muted)]">
              {item.meter.value}%
            </span>
          </div>
        )}
      </div>
      {item.onEdit && (
        <button
          type="button"
          title="Edit"
          onClick={(e) => {
            e.stopPropagation();
            item.onEdit?.();
          }}
          className="flex h-[26px] w-[26px] flex-none items-center justify-center rounded-none border border-transparent text-[color:var(--text-muted)] opacity-0 transition-opacity hover:border-[color:var(--border-default)] hover:bg-[var(--apx-bone)] hover:text-[color:var(--apx-ink)] group-hover:opacity-100"
        >
          <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
            <path
              d="M11 2l3 3-8 8H3v-3z"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.3"
            />
          </svg>
        </button>
      )}
    </div>
  );
}
