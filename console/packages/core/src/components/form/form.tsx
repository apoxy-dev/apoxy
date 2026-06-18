// Reusable wizard/form primitives (the design's `.na-*` / `.ef-*` field kit):
// a numbered section card, a labelled field with hint/error, and text / select /
// segmented inputs. Token-driven so they flip with the theme — the select uses
// an absolutely-positioned chevron drawn in `currentColor` rather than a baked
// background-image, so the arrow is never a hardcoded color. Bespoke wizards
// compose these; they carry no kind-specific knowledge.

import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

export interface FormSectionProps {
  /** Step badge content (e.g. `01`); omit for an unnumbered section. */
  step?: ReactNode
  title: ReactNode
  sub?: ReactNode
  /** Right-aligned header slot (e.g. an "add" affordance). */
  aside?: ReactNode
  children: ReactNode
}

/** A bordered section card with a mist header strip and an ink step badge. */
export function FormSection({ step, title, sub, aside, children }: FormSectionProps) {
  return (
    <section className="border border-[color:var(--border-default)] bg-[var(--apx-white)]">
      <div className="flex items-start gap-[var(--sp-3)] border-b border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[18px] py-[13px]">
        {step != null && (
          <span className="inline-flex h-6 w-6 flex-none items-center justify-center bg-[var(--apx-ink)] text-[length:var(--t-micro)] font-medium tracking-[0.02em] text-[color:var(--text-on-invert)]">
            {step}
          </span>
        )}
        <div className="min-w-0 flex-1">
          <div className="text-[length:var(--t-body-sm)] font-medium leading-[1.25] text-[color:var(--text-primary)]">{title}</div>
          {sub && <div className="mt-[3px] text-[length:var(--t-caption)] leading-[1.4] text-[color:var(--text-muted)]">{sub}</div>}
        </div>
        {aside && <div className="flex-none">{aside}</div>}
      </div>
      <div className="p-[18px]">{children}</div>
    </section>
  )
}

export interface FieldProps {
  label?: ReactNode
  hint?: ReactNode
  error?: ReactNode
  required?: boolean
  htmlFor?: string
  /** Span the full row width. */
  wide?: boolean
  children: ReactNode
}

/** A labelled control with an optional hint, replaced by an error when present. */
export function Field({ label, hint, error, required, htmlFor, wide, children }: FieldProps) {
  return (
    <div className={cn('flex flex-col gap-[6px]', wide && 'w-full')}>
      {label && (
        <label htmlFor={htmlFor} className="text-[length:var(--t-body-sm)] font-medium text-[color:var(--text-primary)]">
          {label}
          {required && <span className="text-[color:var(--apx-coral)]"> *</span>}
        </label>
      )}
      {children}
      {error ? (
        <div className="text-[length:var(--t-micro)] font-medium leading-[1.45] text-[color:var(--apx-coral)]">{error}</div>
      ) : hint ? (
        <div className="text-[length:var(--t-micro)] leading-[1.45] text-[color:var(--text-muted)]">{hint}</div>
      ) : null}
    </div>
  )
}

export interface TextFieldProps {
  id?: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  mono?: boolean
  invalid?: boolean
  disabled?: boolean
  prefix?: ReactNode
  onBlur?: () => void
}

export function TextField({ id, value, onChange, placeholder, mono, invalid, disabled, prefix, onBlur }: TextFieldProps) {
  return (
    <div
      className={cn(
        'flex items-stretch border',
        disabled
          ? 'border-[color:var(--border-default)] bg-[var(--apx-mist)]'
          : 'bg-[var(--apx-bone)] focus-within:bg-[var(--apx-white)] focus-within:shadow-[var(--sh-focus)]',
        invalid
          ? 'border-[color:var(--apx-coral)]'
          : !disabled && 'border-[color:var(--border-default)] focus-within:border-[color:var(--apx-ink)]',
      )}
    >
      {prefix && (
        <span className="inline-flex items-center border-r border-[color:var(--border-default)] bg-[var(--apx-mist)] px-[10px] font-mono text-[length:var(--t-body-sm)] text-[color:var(--text-muted)]">
          {prefix}
        </span>
      )}
      <input
        id={id}
        value={value}
        placeholder={placeholder}
        disabled={disabled}
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        autoCorrect="off"
        onChange={(e) => onChange(e.target.value)}
        onBlur={onBlur}
        className={cn(
          'min-w-0 flex-1 border-0 bg-transparent px-[12px] py-[9px] text-[length:var(--t-body-sm)] text-[color:var(--text-primary)] outline-none placeholder:text-[color:var(--text-disabled)]',
          mono && 'font-mono',
          disabled && 'cursor-not-allowed text-[color:var(--text-muted)]',
        )}
      />
    </div>
  )
}

export interface SelectOption {
  value: string
  label?: string
}

export interface SelectFieldProps {
  id?: string
  value: string
  onChange: (v: string) => void
  options: SelectOption[]
  mono?: boolean
}

export function SelectField({ id, value, onChange, options, mono }: SelectFieldProps) {
  return (
    <div className="relative">
      <select
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          'w-full cursor-pointer appearance-none border border-[color:var(--border-default)] bg-[var(--apx-bone)] py-[9px] pl-[12px] pr-[32px] text-[length:var(--t-body-sm)] leading-[1.3] text-[color:var(--text-primary)] outline-none focus:border-[color:var(--apx-ink)] focus:bg-[var(--apx-white)] focus:shadow-[var(--sh-focus)]',
          mono && 'font-mono',
        )}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label ?? o.value}
          </option>
        ))}
      </select>
      <svg
        width="10"
        height="10"
        viewBox="0 0 10 10"
        fill="none"
        aria-hidden="true"
        className="pointer-events-none absolute right-[12px] top-1/2 -translate-y-1/2 text-[color:var(--text-muted)]"
      >
        <path d="M2 4l3 3 3-3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  )
}

export interface SegFieldProps {
  value: string
  options: string[]
  onChange: (v: string) => void
}

/** A segmented single-choice control (the design's `.ef-seg`). */
export function SegField({ value, options, onChange }: SegFieldProps) {
  return (
    <div className="flex border border-[color:var(--border-default)]">
      {options.map((o) => (
        <button
          key={o}
          type="button"
          onClick={() => onChange(o)}
          className={cn(
            'flex-1 border-r border-[color:var(--border-default)] px-[8px] py-[9px] font-mono text-[length:var(--t-caption)] last:border-r-0',
            o === value
              ? 'bg-[var(--apx-ink)] text-[color:var(--apx-bone)]'
              : 'bg-[var(--apx-white)] text-[color:var(--text-muted)] hover:bg-[var(--apx-bone)]',
          )}
        >
          {o}
        </button>
      ))}
    </div>
  )
}

/** A horizontal row of fields that stack on narrow widths. */
export function FieldRow({ children }: { children: ReactNode }) {
  return <div className="flex flex-col gap-[var(--sp-4)] sm:flex-row sm:items-start [&>*]:sm:min-w-0 [&>*]:sm:flex-1">{children}</div>
}
