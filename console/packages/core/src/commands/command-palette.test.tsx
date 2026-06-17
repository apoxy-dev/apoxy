// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { KeyboardScopeProvider } from '../keyboard/scope-stack'
import { CommandPalette } from './command-palette'
import type { Command } from './commands'

afterEach(cleanup)

function commands(run = vi.fn()): { list: Command[]; run: ReturnType<typeof vi.fn> } {
  const list: Command[] = [
    { id: 'proxies', title: 'Proxies', group: 'Go to', run: () => run('proxies') },
    { id: 'gateways', title: 'Gateways', group: 'Go to', keywords: ['gw'], run: () => run('gateways') },
    { id: 'backends', title: 'Backends', group: 'Go to', run: () => run('backends') },
  ]
  return { list, run }
}

function open(onClose = vi.fn(), list?: Command[]) {
  const c = commands()
  render(
    <KeyboardScopeProvider isMac={false}>
      <CommandPalette open onClose={onClose} commands={list ?? c.list} />
    </KeyboardScopeProvider>,
  )
  return { onClose, run: c.run }
}

describe('CommandPalette', () => {
  it('renders nothing when closed', () => {
    render(
      <KeyboardScopeProvider>
        <CommandPalette open={false} onClose={vi.fn()} commands={commands().list} />
      </KeyboardScopeProvider>,
    )
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('lists all commands when open', () => {
    open()
    expect(screen.getByRole('option', { name: /Proxies/ })).toBeDefined()
    expect(screen.getByRole('option', { name: /Gateways/ })).toBeDefined()
    expect(screen.getByRole('option', { name: /Backends/ })).toBeDefined()
  })

  it('filters as the query changes', () => {
    open()
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'gate' } })
    expect(screen.getByRole('option', { name: /Gateways/ })).toBeDefined()
    expect(screen.queryByRole('option', { name: /Proxies/ })).toBeNull()
  })

  it('runs the top match on Enter and closes', () => {
    const { onClose, run } = open()
    const input = screen.getByRole('combobox')
    fireEvent.change(input, { target: { value: 'back' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(run).toHaveBeenCalledWith('backends')
    expect(onClose).toHaveBeenCalled()
  })

  it('moves the cursor with ArrowDown and runs the highlighted command', () => {
    const { run } = open()
    const input = screen.getByRole('combobox')
    fireEvent.keyDown(input, { key: 'ArrowDown' }) // 0 -> 1 (Gateways)
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(run).toHaveBeenCalledWith('gateways')
  })

  it('runs a command on click', () => {
    const { run } = open()
    fireEvent.click(screen.getByRole('option', { name: /Gateways/ }))
    expect(run).toHaveBeenCalledWith('gateways')
  })

  it('closes on Escape', () => {
    const onClose = vi.fn()
    open(onClose)
    fireEvent.keyDown(screen.getByRole('combobox'), { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })

  it('closes when the backdrop is clicked', () => {
    const onClose = vi.fn()
    open(onClose)
    // The backdrop is the dialog's parent (role=presentation, not in the a11y tree).
    fireEvent.mouseDown(screen.getByRole('dialog').parentElement!)
    expect(onClose).toHaveBeenCalled()
  })

  it('shows an empty state when nothing matches', () => {
    open()
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'zzz' } })
    expect(screen.getByText('No matches')).toBeDefined()
  })

  it('re-selects the top match after a no-match query so Enter still works', () => {
    const { run } = open()
    const input = screen.getByRole('combobox')
    fireEvent.change(input, { target: { value: 'zzz' } }) // 0 matches -> cursor would go to -1
    fireEvent.change(input, { target: { value: 'gate' } }) // 1 match
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(run).toHaveBeenCalledWith('gateways')
  })

  it('renders one header per group even when a group repeats non-contiguously', () => {
    const list: Command[] = [
      { id: 'a1', title: 'Alpha', group: 'A', run: vi.fn() },
      { id: 'b1', title: 'Bravo', group: 'B', run: vi.fn() },
      { id: 'a2', title: 'Anvil', group: 'A', run: vi.fn() },
    ]
    render(
      <KeyboardScopeProvider isMac={false}>
        <CommandPalette open onClose={vi.fn()} commands={list} />
      </KeyboardScopeProvider>,
    )
    // The 'A' group header must appear once, not split around the 'B' entry.
    expect(screen.getAllByText('A')).toHaveLength(1)
  })
})
