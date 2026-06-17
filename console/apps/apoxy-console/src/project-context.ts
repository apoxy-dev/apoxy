// Project / host context for the chrome (the breadcrumb root), derived from the
// same build-time env as the console client. Kept separate from console-client
// so reading the label doesn't construct a client (the dev mock entry builds its
// own). Origin and project come from VITE_APOXY_API_URL / VITE_APOXY_PROJECT_ID,
// defaulting to the serving origin so a co-hosted console "just works".

const env = (import.meta as { env?: Record<string, string | undefined> }).env ?? {}
const origin = typeof window !== 'undefined' ? window.location.origin : ''

// `||` (not `??`) so a defined-but-empty env var falls back rather than being used verbatim.
export const baseUrl = env.VITE_APOXY_API_URL || origin
export const projectId = env.VITE_APOXY_PROJECT_ID || 'default'

function hostOf(u: string): string {
  try {
    return new URL(u).hostname
  } catch {
    return ''
  }
}

const host = hostOf(baseUrl)
// `new URL().hostname` returns IPv6 in bracket form (`[::1]`).
const loopback = host === '' || host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]'

/**
 * The leading breadcrumb names the deployment:
 *  - an explicit project slug (VITE_APOXY_PROJECT_ID) wins;
 *  - else `localhost` when talking to a loopback apiserver on the box;
 *  - else the apiserver host (a self-hosted deployment behind a real hostname),
 *    which is more meaningful than the `default` project fallback.
 */
export const rootCrumbLabel = projectId !== 'default' ? projectId : loopback ? 'localhost' : host
