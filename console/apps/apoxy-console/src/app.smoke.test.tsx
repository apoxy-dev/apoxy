import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Button } from '@apoxy/console-core'

// The Foundation smoke test (CI canary): if @apoxy/console-core resolves
// across the workspace boundary, its TSX compiles, and cn() runs, this passes.
describe('console-core smoke', () => {
  it('renders a core primitive with token-referencing classes', () => {
    render(<Button>Primary</Button>)
    const btn = screen.getByRole('button', { name: 'Primary' })
    expect(btn).toBeTruthy()
    expect(btn.className).toContain('bg-[var(--apx-ink)]')
    expect(btn.className).toContain('rounded-none')
  })
})
