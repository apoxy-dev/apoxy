// RequestDecorator — the environment seam that decorates every outgoing API
// request with headers, a base path, and project scoping. It
// replaces the dashboard's `baseURL.replace('PROJECT_ID', projectId)` axios
// hack and the ad-hoc project-header weaving.
//
// Its second job is to expose a stable `scopeKey`: the WatchManager
// keys watches by `(scopeKey, gvr)` and tears down + rebuilds them when the key
// changes, which is how a project switch is handled structurally instead of
// with a `window.location.reload()`.

/** An outgoing request before decoration: a host-relative k8s API path
 *  (already including any query string), its method, and caller headers
 *  (content negotiation, etc.). */
export interface DecorateInput {
  path: string
  method: string
  headers: Headers
}

/** The decorated request: an absolute URL to fetch and the merged headers. */
export interface DecorateResult {
  url: string
  headers: Headers
}

export interface RequestDecorator {
  /**
   * Stable identity of the current request scope (typically the project). The
   * WatchManager rebuilds its watches when this value changes; two decorators
   * with the same `scopeKey` must produce equivalent scoping.
   */
  readonly scopeKey: string

  /** Resolve the absolute URL and merge in scoping/auth headers. */
  decorate(req: DecorateInput): DecorateResult
}

/** Legacy and modern placeholders substituted with the project id in `baseUrl`. */
const PROJECT_PLACEHOLDERS = ['{projectId}', 'PROJECT_ID']

export interface ProjectRequestDecoratorOptions {
  /**
   * API origin/base, e.g. `https://api.apoxy.dev`. May embed a `{projectId}`
   * (or legacy `PROJECT_ID`) placeholder that is substituted with the project
   * id; if it has no placeholder the project id is sent as a header instead.
   */
  baseUrl: string
  /** The project that scopes these requests. */
  projectId: string
  /** Header carrying the project id when `baseUrl` has no placeholder.
   *  Defaults to `X-Apoxy-Project-Id`. */
  projectHeader?: string
  /** Static headers attached to every request (e.g. a fixed API key). */
  headers?: HeadersInit
  /**
   * Headers resolved lazily on *every* request — evaluated at decorate time so
   * a refreshed auth token is picked up on the next request or watch reconnect
   * without rebuilding anything, so an auth refresh resumes seamlessly.
   */
  dynamicHeaders?: () => HeadersInit | undefined
}

/**
 * The default decorator: scopes requests to a single project by substituting a
 * `baseUrl` placeholder (or attaching a project header) and merges static +
 * lazily-resolved headers. Its `scopeKey` is `${resolvedBase}|${projectId}`, so
 * switching project (or origin) changes the identity the WatchManager watches.
 */
export class ProjectRequestDecorator implements RequestDecorator {
  readonly scopeKey: string
  private readonly origin: string
  private readonly hasPlaceholder: boolean
  private readonly opts: ProjectRequestDecoratorOptions

  constructor(opts: ProjectRequestDecoratorOptions) {
    this.opts = opts
    this.hasPlaceholder = PROJECT_PLACEHOLDERS.some((p) => opts.baseUrl.includes(p))
    this.origin = stripTrailingSlash(substituteProject(opts.baseUrl, opts.projectId))
    this.scopeKey = `${this.origin}|${opts.projectId}`
  }

  decorate(req: DecorateInput): DecorateResult {
    const headers = new Headers(this.opts.headers)
    const dynamic = this.opts.dynamicHeaders?.()
    if (dynamic) for (const [k, v] of new Headers(dynamic)) headers.set(k, v)
    if (!this.hasPlaceholder) {
      headers.set(this.opts.projectHeader ?? 'X-Apoxy-Project-Id', this.opts.projectId)
    }
    // Caller headers (Content-Type/Accept) win over decorator-supplied ones.
    for (const [k, v] of req.headers) headers.set(k, v)
    return { url: this.origin + ensureLeadingSlash(req.path), headers }
  }
}

function substituteProject(baseUrl: string, projectId: string): string {
  let out = baseUrl
  for (const p of PROJECT_PLACEHOLDERS) out = out.split(p).join(projectId)
  return out
}

function stripTrailingSlash(s: string): string {
  return s.endsWith('/') ? s.slice(0, -1) : s
}

function ensureLeadingSlash(s: string): string {
  return s.startsWith('/') ? s : '/' + s
}
