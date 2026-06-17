// The app's single ConsoleClient: a GVR client + QueryClient + WatchManager
// scoped to one project. Origin and project come from build-time env
// (VITE_APOXY_API_URL / VITE_APOXY_PROJECT_ID), defaulting to the serving
// origin so a co-hosted console "just works".

import { createConsoleClient, ProjectRequestDecorator, type ConsoleClient } from '@apoxy/console-core'

const env = (import.meta as { env?: Record<string, string | undefined> }).env ?? {}
const origin = typeof window !== 'undefined' ? window.location.origin : ''
// `||` (not `??`) so a defined-but-empty env var falls back rather than being used verbatim.
const baseUrl = env.VITE_APOXY_API_URL || origin
const projectId = env.VITE_APOXY_PROJECT_ID || 'default'

export const consoleClient: ConsoleClient = createConsoleClient({
  decorator: new ProjectRequestDecorator({ baseUrl, projectId }),
})
