// Breadcrumb trail (APO-775), rendered from the model buildBreadcrumbs derives
// from the registry + route. Intermediate crumbs link via the router seam; the
// final crumb is the current location (aria-current="page").

import { Fragment } from 'react'
import { cn } from '../../lib/cn'
import { useLink } from './link-context'
import type { Breadcrumb } from '../../registry/nav'

export interface BreadcrumbsProps {
  items: Breadcrumb[]
  className?: string
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
            {c.to && !last ? (
              <Link
                to={c.to}
                className="text-[color:var(--text-muted)] no-underline hover:text-[color:var(--text-primary)]"
              >
                {c.label}
              </Link>
            ) : (
              <span
                aria-current={last ? 'page' : undefined}
                className={last ? 'font-medium text-[color:var(--text-primary)]' : undefined}
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
