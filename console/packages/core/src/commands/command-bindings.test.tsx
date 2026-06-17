// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render } from '@testing-library/react'
import { KeyboardScopeProvider } from '../keyboard/scope-stack'
import { useCommandKeyBindings } from './command-bindings'
import type { Command } from './commands'

afterEach(cleanup)

function Harness({ commands }: { commands: Command[] }) {
  useCommandKeyBindings(commands)
  return null
}

describe('useCommandKeyBindings', () => {
  it('fires a command from its g-sequence binding', () => {
    const run = vi.fn()
    const commands: Command[] = [
      { id: 'nav:proxies', title: 'Proxies', keys: 'g p', run },
      { id: 'new:proxies', title: 'New Proxy', run: () => {} }, // no keys -> palette-only
    ]
    render(
      <KeyboardScopeProvider isMac={false}>
        <Harness commands={commands} />
      </KeyboardScopeProvider>,
    )
    fireEvent.keyDown(document.body, { key: 'g' }) // pending prefix
    fireEvent.keyDown(document.body, { key: 'p' }) // completes `g p`
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('ignores commands without a keys spec (palette-only)', () => {
    const run = vi.fn()
    render(
      <KeyboardScopeProvider isMac={false}>
        <Harness commands={[{ id: 'x', title: 'X', run }]} />
      </KeyboardScopeProvider>,
    )
    fireEvent.keyDown(document.body, { key: 'x' })
    expect(run).not.toHaveBeenCalled()
  })
})
