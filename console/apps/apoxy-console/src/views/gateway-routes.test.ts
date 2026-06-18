import { describe, expect, it } from 'vitest'
import {
  attachesToGateway,
  backendMatchesQuery,
  listenerHealth,
  routeHealth,
  routeId,
  routeMatchesQuery,
  routesForListener,
  ruleMatchesQuery,
  ruleMatchSummary,
  type GatewayObject,
  type ParentRef,
  type RouteObject,
} from './gateway-routes'

const gw: GatewayObject = {
  metadata: { name: 'edge', namespace: 'default' },
  spec: {
    gatewayClassName: 'apoxy',
    listeners: [
      { name: 'http', port: 80, protocol: 'HTTP' },
      { name: 'https', port: 443, protocol: 'HTTPS' },
    ],
  },
  status: {
    listeners: [
      { name: 'http', attachedRoutes: 2, conditions: [{ type: 'Programmed', status: 'True' }] },
      { name: 'https', attachedRoutes: 0, conditions: [{ type: 'Programmed', status: 'False' }] },
    ],
  },
}

function route(name: string, parentRefs: ParentRef[], extra: Partial<NonNullable<RouteObject['spec']>> = {}): RouteObject {
  return { kind: 'HTTPRoute', metadata: { name, namespace: 'default' }, spec: { parentRefs, ...extra } }
}

describe('attachesToGateway', () => {
  it('matches a parentRef by name in the same namespace', () => {
    expect(attachesToGateway(route('a', [{ name: 'edge' }]), gw)).toBe(true)
  })
  it('rejects a parentRef naming a different gateway', () => {
    expect(attachesToGateway(route('a', [{ name: 'other' }]), gw)).toBe(false)
  })
  it('rejects a non-Gateway parentRef kind', () => {
    expect(attachesToGateway(route('a', [{ name: 'edge', kind: 'Service' }]), gw)).toBe(false)
  })
  it('honors an explicit cross-namespace parentRef namespace', () => {
    const r: RouteObject = { metadata: { name: 'a', namespace: 'other' }, spec: { parentRefs: [{ name: 'edge', namespace: 'default' }] } }
    expect(attachesToGateway(r, gw)).toBe(true)
  })
  it('attaches when any one of several parentRefs matches', () => {
    expect(attachesToGateway(route('a', [{ name: 'other' }, { name: 'edge' }]), gw)).toBe(true)
  })
})

describe('routesForListener', () => {
  const scoped = route('scoped', [{ name: 'edge', sectionName: 'https' }])
  const unscoped = route('unscoped', [{ name: 'edge' }])
  const routes = [scoped, unscoped]

  it('binds an unscoped route to every listener', () => {
    expect(routesForListener(routes, gw, 'http').map((r) => r.metadata.name)).toEqual(['unscoped'])
  })
  it('binds a sectionName-scoped route only to its listener', () => {
    expect(routesForListener(routes, gw, 'https').map((r) => r.metadata.name)).toEqual(['scoped', 'unscoped'])
  })
  it('returns nothing when no listener is selected', () => {
    expect(routesForListener(routes, gw, null)).toEqual([])
  })

  // Divergence guards: routesForListener must apply the SAME ref-matching as
  // attachesToGateway (kind + namespace), not just name — otherwise a stray
  // same-name ref with an unset sectionName would misbind the route everywhere.
  it('does not bind a route whose only same-name ref is a non-Gateway kind', () => {
    const svc = route('svc', [{ name: 'edge', kind: 'Service' }])
    expect(routesForListener([svc], gw, 'http')).toEqual([])
    expect(routesForListener([svc], gw, 'https')).toEqual([])
  })
  it('applies sectionName to the gateway-targeting ref, not a stray same-name ref', () => {
    const mixed = route('mixed', [
      { name: 'edge', kind: 'Service' }, // shares the name but must not bind via its null sectionName
      { name: 'edge', sectionName: 'http' }, // the real Gateway ref decides placement
    ])
    expect(routesForListener([mixed], gw, 'http').map((r) => r.metadata.name)).toEqual(['mixed'])
    expect(routesForListener([mixed], gw, 'https')).toEqual([])
  })
})

describe('listenerHealth', () => {
  it('is ok when Programmed=True', () => expect(listenerHealth(gw, 'http')).toBe('ok'))
  it('is err when Programmed=False', () => expect(listenerHealth(gw, 'https')).toBe('err'))
  it('is warn for an unknown listener', () => expect(listenerHealth(gw, 'mystery')).toBe('warn'))
})

describe('routeHealth', () => {
  const withStatus = (conds: Array<{ type: string; status: string }>): RouteObject => ({
    kind: 'HTTPRoute',
    metadata: { name: 'r', namespace: 'default' },
    spec: {},
    status: { parents: [{ conditions: conds }] },
  })
  it('is ok when Accepted and ResolvedRefs are True', () => {
    expect(
      routeHealth(withStatus([{ type: 'Accepted', status: 'True' }, { type: 'ResolvedRefs', status: 'True' }])),
    ).toBe('ok')
  })
  it('is err when any relevant condition is False', () => {
    expect(
      routeHealth(withStatus([{ type: 'Accepted', status: 'False' }, { type: 'ResolvedRefs', status: 'True' }])),
    ).toBe('err')
  })
  it('is warn when the route has no status yet', () => {
    expect(routeHealth(route('a', [{ name: 'edge' }]))).toBe('warn')
  })
})

describe('routeId', () => {
  it('namespaces the id by kind + namespace + name', () => {
    expect(routeId(route('a', [{ name: 'edge' }]))).toBe('HTTPRoute/default/a')
  })
})

describe('query matching', () => {
  const r = route('web-app', [{ name: 'edge' }], {
    hostnames: ['app.apoxy.dev'],
    rules: [
      { matches: [{ path: { type: 'PathPrefix', value: '/api' } }], backendRefs: [{ name: 'api-svc', port: 9090 }] },
    ],
  })

  it('matches a route by hostname', () => expect(routeMatchesQuery(r, 'apoxy')).toBe(true))
  it('matches a route by a backend nested in one of its rules', () => expect(routeMatchesQuery(r, 'api-svc')).toBe(true))
  it('matches a route by a rule path', () => expect(routeMatchesQuery(r, '/api')).toBe(true))
  it('does not match an unrelated query', () => expect(routeMatchesQuery(r, 'zzz')).toBe(false))
  it('an empty query matches everything', () => expect(routeMatchesQuery(r, '')).toBe(true))

  it('matches a rule by its backend', () =>
    expect(ruleMatchesQuery(r.spec!.rules![0]!, 'HTTPRoute', 'api-svc')).toBe(true))
  it('matches a rule by its path match', () =>
    expect(ruleMatchesQuery(r.spec!.rules![0]!, 'HTTPRoute', '/api')).toBe(true))
  it('does not match a rule on an unrelated query', () =>
    expect(ruleMatchesQuery(r.spec!.rules![0]!, 'HTTPRoute', 'zzz')).toBe(false))

  it('matches a backend by name', () => expect(backendMatchesQuery({ name: 'api-svc', port: 9090 }, 'api-svc')).toBe(true))
  it('matches a backend by port', () => expect(backendMatchesQuery({ name: 'api-svc', port: 9090 }, '9090')).toBe(true))
})

describe('ruleMatchSummary', () => {
  it('summarizes an HTTP path match', () => {
    expect(ruleMatchSummary({ matches: [{ path: { type: 'PathPrefix', value: '/api' } }] }, 'HTTPRoute')).toBe('PathPrefix /api')
  })
  it('summarizes a gRPC method match', () => {
    expect(ruleMatchSummary({ matches: [{ method: { service: 'pkg.Svc', method: 'Call' } }] }, 'GRPCRoute')).toBe('pkg.Svc/Call')
  })
  it('falls back to default with no matches', () => {
    expect(ruleMatchSummary({}, 'HTTPRoute')).toBe('default')
  })
})
