import { useEffect } from 'react'

// PostHog product analytics for the Apoxy consoles. The project API key (phc_
// prefix) is write-only and is designed to ship in client code; events are sent
// through our own first-party reverse proxy at e.apoxy.dev, which forwards to
// PostHog. A first-party host keeps analytics working when content blockers drop
// requests to *.posthog.com. posthog-js is loaded lazily (dynamic import,
// browser-only) so it never weighs on the initial bundle and never runs during
// SSR or tests.
//
// This module is deliberately router-agnostic: consumers feed the current
// location string to useAnalyticsPageviews, so any router (both the apoxy and
// clrk consoles use @tanstack/react-router) drives pageview capture without core
// taking a dependency on a router package.
const POSTHOG_KEY = 'phc_1vxv4W6aylabZGC66cY1KnzYWkFJp9QQWKC5jyfBiVO'

let initialized = false

// Lazily imports posthog-js and inits it at most once. Returns null off the
// browser (SSR, tests) so every caller degrades to a no-op there.
function load(): Promise<typeof import('posthog-js')['default']> | null {
  if (typeof window === 'undefined') return null
  return import('posthog-js').then(({ default: posthog }) => {
    if (!initialized) {
      initialized = true
      posthog.init(POSTHOG_KEY, {
        api_host: 'https://e.apoxy.dev',
        ui_host: 'https://us.posthog.com',
        // Anonymous by default: pageviews never mint a person profile unless a
        // consumer later calls posthog.identify(). Keeps self-hosted consoles
        // from creating a person record for every operator who opens the UI.
        person_profiles: 'identified_only',
        // Captured manually below so the initial load and SPA navigations are
        // counted uniformly, with no double-count.
        capture_pageview: false,
      })
    }
    return posthog
  })
}

// Captures a single $pageview for the current location. Returns a canceller that
// suppresses the capture if the caller navigates or unmounts before the lazy
// import resolves, so a fast route change never emits a stale pageview. (Under
// React StrictMode this also collapses the dev double-invoke to one capture.)
export function capturePageview(): () => void {
  let cancelled = false
  const pending = load()
  if (pending) {
    void pending.then((posthog) => {
      if (!cancelled) posthog.capture('$pageview')
    })
  }
  return () => {
    cancelled = true
  }
}

// Captures a named product event with optional properties. Fire-and-forget; a
// no-op off the browser.
export function captureEvent(name: string, properties?: Record<string, unknown>): void {
  const pending = load()
  if (pending) void pending.then((posthog) => posthog.capture(name, properties))
}

// Captures a $pageview on mount and on every location change. Consumers pass
// their router's current location (e.g. TanStack Router's useLocation().href),
// keeping this hook independent of any specific router.
export function useAnalyticsPageviews(location: string): void {
  useEffect(() => capturePageview(), [location])
}
