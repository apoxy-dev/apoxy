import { describe, expect, it } from 'vitest'
import { ProjectRequestDecorator } from './request-decorator'

function headers(): Headers {
  return new Headers()
}

describe('ProjectRequestDecorator', () => {
  it('substitutes a {projectId} placeholder in the base URL', () => {
    const d = new ProjectRequestDecorator({ baseUrl: 'https://api.test/{projectId}', projectId: 'p1' })
    const { url } = d.decorate({ path: '/apis/g/v/r', method: 'GET', headers: headers() })
    expect(url).toBe('https://api.test/p1/apis/g/v/r')
  })

  it('substitutes the legacy PROJECT_ID placeholder and adds a leading slash', () => {
    const d = new ProjectRequestDecorator({ baseUrl: 'https://api.test/PROJECT_ID', projectId: 'p2' })
    const { url } = d.decorate({ path: 'apis/g/v/r', method: 'GET', headers: headers() })
    expect(url).toBe('https://api.test/p2/apis/g/v/r')
  })

  it('sends a project header when the base URL has no placeholder', () => {
    const d = new ProjectRequestDecorator({ baseUrl: 'https://api.test', projectId: 'p3' })
    const { url, headers: h } = d.decorate({ path: '/x', method: 'GET', headers: headers() })
    expect(url).toBe('https://api.test/x')
    expect(h.get('X-Apoxy-Project-Id')).toBe('p3')
  })

  it('resolves dynamic headers per call so a refreshed token is picked up', () => {
    let token = 'a'
    const d = new ProjectRequestDecorator({
      baseUrl: 'https://api.test',
      projectId: 'p',
      headers: { 'X-Static': 's' },
      dynamicHeaders: () => ({ Authorization: `Bearer ${token}` }),
    })
    expect(d.decorate({ path: '/x', method: 'GET', headers: headers() }).headers.get('authorization')).toBe('Bearer a')
    token = 'b'
    const out = d.decorate({ path: '/x', method: 'GET', headers: headers() }).headers
    expect(out.get('authorization')).toBe('Bearer b')
    expect(out.get('x-static')).toBe('s')
  })

  it('lets caller headers win over decorator-supplied ones', () => {
    const d = new ProjectRequestDecorator({ baseUrl: 'https://api.test', projectId: 'p', headers: { Accept: 'text/plain' } })
    const h = headers()
    h.set('Accept', 'application/json')
    expect(d.decorate({ path: '/x', method: 'GET', headers: h }).headers.get('accept')).toBe('application/json')
  })

  it('scopeKey changes with project and origin, matches for identical inputs', () => {
    const a = new ProjectRequestDecorator({ baseUrl: 'https://api.test', projectId: 'p1' })
    const b = new ProjectRequestDecorator({ baseUrl: 'https://api.test', projectId: 'p2' })
    const c = new ProjectRequestDecorator({ baseUrl: 'https://api.test', projectId: 'p1' })
    const d = new ProjectRequestDecorator({ baseUrl: 'https://other.test', projectId: 'p1' })
    expect(a.scopeKey).not.toBe(b.scopeKey)
    expect(a.scopeKey).not.toBe(d.scopeKey)
    expect(a.scopeKey).toBe(c.scopeKey)
  })
})
