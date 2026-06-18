// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render } from '@testing-library/react'
import { YamlCode } from './yaml-code'

afterEach(cleanup)

describe('YamlCode', () => {
  it('renders one code line per source line', () => {
    const { container } = render(<YamlCode text={'a: 1\nb: 2\nc: 3'} />)
    expect(container.querySelectorAll('code')).toHaveLength(3)
  })

  it('tints a key/value line into separate spans', () => {
    const { container } = render(<YamlCode text={'name: edge'} />)
    const code = container.querySelector('code')!
    // key + colon + value are distinct spans, not one flat string.
    expect(code.querySelectorAll('span').length).toBeGreaterThanOrEqual(3)
    expect(code.textContent).toContain('name')
    expect(code.textContent).toContain('edge')
  })

  it('renders an empty document as a single line', () => {
    const { container } = render(<YamlCode text={''} />)
    expect(container.querySelectorAll('code')).toHaveLength(1)
  })
})
