// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { KeyboardScopeProvider } from '../../keyboard/scope-stack'
import { ConfirmDialog } from './confirm-dialog'

afterEach(cleanup)

const wrap = (ui: ReactNode) => render(<KeyboardScopeProvider>{ui}</KeyboardScopeProvider>)

describe('ConfirmDialog', () => {
  it('renders nothing when closed', () => {
    wrap(<ConfirmDialog open={false} title="Delete?" onConfirm={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })

  it('confirms and cancels via the buttons', () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    wrap(<ConfirmDialog open title="Delete?" confirmLabel="Delete" onConfirm={onConfirm} onCancel={onCancel} />)
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(onConfirm).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('cancels on Escape (modal scope)', () => {
    const onCancel = vi.fn()
    wrap(<ConfirmDialog open title="Delete?" onConfirm={vi.fn()} onCancel={onCancel} />)
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onCancel).toHaveBeenCalled()
  })

  it('shows the error and a busy label while pending', () => {
    wrap(<ConfirmDialog open title="Delete?" confirmLabel="Delete" pending error="boom" onConfirm={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.getByText('boom')).toBeDefined()
    expect((screen.getByRole('button', { name: 'Working…' }) as HTMLButtonElement).disabled).toBe(true)
  })
})
