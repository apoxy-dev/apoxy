// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { KeyboardScopeProvider, useKeyboardScope, type KeyBinding } from './scope-stack'

afterEach(cleanup)

function Scope({
  level,
  bindings,
  modal,
  enabled,
}: {
  level: 'global' | 'view' | 'tray' | 'dialog'
  bindings: KeyBinding[]
  modal?: boolean
  enabled?: boolean
}) {
  useKeyboardScope({ level, bindings, modal, enabled })
  return null
}

function provider(children: ReactNode, isMac = false, timeout = 1000) {
  return render(
    <KeyboardScopeProvider isMac={isMac} sequenceTimeoutMs={timeout}>
      {children}
    </KeyboardScopeProvider>,
  )
}

describe('scope stack dispatch', () => {
  it('runs a matching chord binding', () => {
    const run = vi.fn()
    provider(<Scope level="global" bindings={[{ keys: 'mod+k', run }]} />)
    fireEvent.keyDown(document.body, { key: 'k', ctrlKey: true })
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('does not fire when modifiers do not match', () => {
    const run = vi.fn()
    provider(<Scope level="global" bindings={[{ keys: 'mod+k', run }]} />)
    fireEvent.keyDown(document.body, { key: 'k' })
    expect(run).not.toHaveBeenCalled()
  })

  it('prefers the higher-priority scope for the same chord', () => {
    const view = vi.fn()
    const dialog = vi.fn()
    provider(
      <>
        <Scope level="view" bindings={[{ keys: 'enter', run: view }]} />
        <Scope level="dialog" bindings={[{ keys: 'enter', run: dialog }]} />
      </>,
    )
    fireEvent.keyDown(document.body, { key: 'Enter' })
    expect(dialog).toHaveBeenCalledTimes(1)
    expect(view).not.toHaveBeenCalled()
  })

  it('a modal scope shadows lower scopes even for keys it does not bind', () => {
    const viewNav = vi.fn()
    provider(
      <>
        <Scope level="view" bindings={[{ keys: 'j', run: viewNav }]} />
        {/* tray is modal by default and binds only escape */}
        <Scope level="tray" bindings={[{ keys: 'escape', run: vi.fn() }]} />
      </>,
    )
    fireEvent.keyDown(document.body, { key: 'j' })
    expect(viewNav).not.toHaveBeenCalled()
  })

  it('runs a g-sequence binding across two keypresses', () => {
    const run = vi.fn()
    provider(<Scope level="view" bindings={[{ keys: 'g i', run }]} />)
    fireEvent.keyDown(document.body, { key: 'g' })
    expect(run).not.toHaveBeenCalled()
    fireEvent.keyDown(document.body, { key: 'i' })
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('abandons a sequence after the timeout', () => {
    vi.useFakeTimers()
    try {
      const run = vi.fn()
      provider(<Scope level="view" bindings={[{ keys: 'g i', run }]} />, false, 800)
      fireEvent.keyDown(document.body, { key: 'g' })
      vi.advanceTimersByTime(900)
      fireEvent.keyDown(document.body, { key: 'i' })
      expect(run).not.toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })

  it('retries a fresh chord when a dead sequence is abandoned', () => {
    const seq = vi.fn()
    const j = vi.fn()
    provider(
      <Scope
        level="view"
        bindings={[
          { keys: 'g i', run: seq },
          { keys: 'j', run: j },
        ]}
      />,
    )
    fireEvent.keyDown(document.body, { key: 'g' }) // starts a pending prefix
    fireEvent.keyDown(document.body, { key: 'j' }) // not 'g i' — should fall back to 'j'
    expect(seq).not.toHaveBeenCalled()
    expect(j).toHaveBeenCalledTimes(1)
  })

  it('starts a fresh sequence after a dead prefix instead of inheriting it', () => {
    const gi = vi.fn()
    const xy = vi.fn()
    provider(
      <Scope
        level="view"
        bindings={[
          { keys: 'g i', run: gi },
          { keys: 'x y', run: xy },
        ]}
      />,
    )
    fireEvent.keyDown(document.body, { key: 'g' }) // pending [g]
    fireEvent.keyDown(document.body, { key: 'x' }) // [g,x] dead -> retry, [x] is a fresh prefix
    fireEvent.keyDown(document.body, { key: 'y' }) // should complete x y, not stay stuck on the g prefix
    expect(gi).not.toHaveBeenCalled()
    expect(xy).toHaveBeenCalledTimes(1)
  })

  it('suppresses bare-letter bindings while typing in an input', () => {
    const j = vi.fn()
    const save = vi.fn()
    const { container } = provider(
      <>
        <Scope level="view" bindings={[{ keys: 'j', run: j }]} />
        <Scope level="global" bindings={[{ keys: 'mod+s', run: save, allowInEditable: true }]} />
        <input data-testid="field" />
      </>,
    )
    const input = container.querySelector('input')!
    fireEvent.keyDown(input, { key: 'j' })
    expect(j).not.toHaveBeenCalled()
    fireEvent.keyDown(input, { key: 's', ctrlKey: true })
    expect(save).toHaveBeenCalledTimes(1)
  })

  it('ignores a disabled scope', () => {
    const run = vi.fn()
    provider(<Scope level="global" bindings={[{ keys: 'k', run }]} enabled={false} />)
    fireEvent.keyDown(document.body, { key: 'k' })
    expect(run).not.toHaveBeenCalled()
  })
})
