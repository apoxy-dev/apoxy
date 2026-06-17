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

const DefaultLink: LinkComponent = ({ to, children, ...rest }) => (
  <a href={to} {...rest}>
    {children}
  </a>
)

const LinkContext = createContext<LinkComponent>(DefaultLink)

export function LinkProvider({
  component,
  children,
}: {
  component: LinkComponent
  children: ReactNode
}) {
  return <LinkContext.Provider value={component}>{children}</LinkContext.Provider>
}

export function useLink(): LinkComponent {
  return useContext(LinkContext)
}
