import { describe, expect, it } from 'vitest'
import { cn } from './cn'

describe('cn', () => {
  it('de-dupes conflicting tailwind utilities, last wins', () => {
    expect(cn('px-2', 'px-4')).toBe('px-4')
  })

  it('drops falsy values and keeps token-referencing arbitrary classes', () => {
    expect(cn('bg-[var(--apx-ink)]', false && 'hidden', undefined)).toBe('bg-[var(--apx-ink)]')
  })
})
