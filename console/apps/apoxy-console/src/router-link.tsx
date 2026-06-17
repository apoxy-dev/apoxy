// Adapts console-core's router seam to TanStack Router. Renders a real <a href>
// (so middle/⌘-click open a new tab) and intercepts plain left-clicks for
// client-side navigation. The registry produces concrete pathnames, so `to` is
// a resolved path string — cast past TanStack's typed-route union deliberately.

import { useRouter } from '@tanstack/react-router'
import type { MouseEvent } from 'react'
import type { NavLinkProps } from '@apoxy/console-core'

export function RouterLink({ to, className, title, children, onClick, ...rest }: NavLinkProps) {
  const router = useRouter()
  const handleClick = (e: MouseEvent) => {
    onClick?.(e)
    if (e.defaultPrevented) return
    // Let the browser handle new-tab / new-window intents.
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    e.preventDefault()
    void router.navigate({ to: to as never })
  }
  return (
    <a href={to} className={className} title={title} onClick={handleClick} {...rest}>
      {children}
    </a>
  )
}
