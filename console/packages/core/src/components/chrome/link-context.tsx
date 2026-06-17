// The single router seam. Core chrome (sidebar, breadcrumbs) and the generic
// renderers link via `useLink()` so they stay router-agnostic and render in
// tests without a router. The app supplies a TanStack-Router-backed adapter
// through <LinkProvider>; with no provider, links degrade to plain <a>.

import { createContext, useContext } from 'react'
import type { ComponentType, MouseEvent, ReactNode } from 'react'

export interface NavLinkProps {
  to: string
  className?: string
  title?: string
  'aria-current'?: 'page' | undefined
  'aria-label'?: string
  onClick?: (e: MouseEvent) => void
  children: ReactNode
}

export type LinkComponent = ComponentType<NavLinkProps>

/** Programmatic navigation — the keyboard counterpart to clicking a {@link LinkComponent}. */
export type NavigateFn = (to: string) => void

const DefaultLink: LinkComponent = ({ to, children, ...rest }) => (
  <a href={to} {...rest}>
    {children}
  </a>
)

/** With no provider, navigate falls back to a full-page assign (or a no-op in SSR). */
const defaultNavigate: NavigateFn = (to) => {
  if (typeof window !== 'undefined') window.location.assign(to)
}

const LinkContext = createContext<LinkComponent>(DefaultLink)
const NavigateContext = createContext<NavigateFn>(defaultNavigate)

export function LinkProvider({
  component,
  navigate,
  children,
}: {
  component: LinkComponent
  /** Programmatic navigation for keyboard activation / the command palette. */
  navigate?: NavigateFn
  children: ReactNode
}) {
  const link = <LinkContext.Provider value={component}>{children}</LinkContext.Provider>
  return navigate ? <NavigateContext.Provider value={navigate}>{link}</NavigateContext.Provider> : link
}

export function useLink(): LinkComponent {
  return useContext(LinkContext)
}

export function useNavigate(): NavigateFn {
  return useContext(NavigateContext)
}
