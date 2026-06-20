// Breadcrumb trail (APO-775), rendered from the model buildBreadcrumbs derives
// from the registry + route. Intermediate crumbs link via the router seam; the
// final crumb is the current location (aria-current="page").

import { Fragment } from 'react'
import { cn } from '../../lib/cn'
import { useLink } from './link-context'
import type { Breadcrumb, BreadcrumbSwitch } from '../../registry/nav'

export interface BreadcrumbsProps {
  items: Breadcrumb[]
  className?: string
}

/**
 * The leaf crumb as an object-switcher: the current label with a chevron, over
 * an invisible native `<select>` whose options jump to a sibling. The native
 * control keeps it keyboard- and screen-reader-accessible for free.
 */
function CrumbSwitch({
  label,
  switcher,
}: {
  label: string
  switcher: BreadcrumbSwitch
}) {
  return (
    <span className="relative -ml-[4px] inline-flex cursor-pointer items-center gap-[4px] border border-transparent py-[2px] pl-[4px] pr-[22px] hover:border-[color:var(--border-default)] hover:bg-[var(--apx-mist)]">
      <span
        aria-current="page"
        className="pointer-events-none font-medium text-[color:var(--text-primary)]"
      >
        {label}
      </span>
      <svg
        aria-hidden="true"
        width="9"
        height="9"
        viewBox="0 0 9 9"
        fill="none"
        className="pointer-events-none absolute right-[6px] top-1/2 -translate-y-1/2 text-[color:var(--text-muted)]"
      >
        <path
          d="M1.5 3l3 3 3-3"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <select
        aria-label={switcher.ariaLabel ?? 'Switch object'}
        value={switcher.value}
        onChange={(e) => switcher.onSelect(e.target.value)}
        className="absolute inset-0 h-full w-full cursor-pointer appearance-none border-0 bg-transparent text-[length:var(--t-caption)] opacity-0"
      >
        {switcher.options.map((o) => (
          <option key={o.id} value={o.id}>
            {o.sublabel ? `${o.label}  ·  ${o.sublabel}` : o.label}
          </option>
        ))}
      </select>
    </span>
  )
}

export function Breadcrumbs({ items, className }: BreadcrumbsProps) {
  const Link = useLink()
  return (
    <nav
      aria-label="Breadcrumb"
      className={cn(
        'flex items-center gap-[var(--sp-2)] text-[length:var(--t-caption)] text-[color:var(--text-muted)]',
        className,
      )}
    >
      {items.map((c, i) => {
        const last = i === items.length - 1
        return (
          <Fragment key={`${c.label}-${i}`}>
            {i > 0 && <span className="text-[color:var(--apx-stone)]">/</span>}
            {c.switcher ? (
              <CrumbSwitch label={c.label} switcher={c.switcher} />
            ) : c.to && !last ? (
              <Link
                to={c.to}
                className="text-[color:var(--text-muted)] no-underline hover:text-[color:var(--text-primary)]"
              >
                {c.label}
              </Link>
            ) : (
              <span
                aria-current={last ? 'page' : undefined}
                className={
                  last
                    ? 'font-medium text-[color:var(--text-primary)]'
                    : undefined
                }
              >
                {c.label}
              </span>
            )}
          </Fragment>
        )
      })}
    </nav>
  )
}
