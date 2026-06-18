// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { DropdownMenu, type DropdownItem } from './dropdown-menu'

afterEach(cleanup)

function items(onA = vi.fn(), onB = vi.fn()): DropdownItem[] {
  return [
    { id: 'a', label: 'Action A', sub: 'does A', kbd: 'A', onSelect: onA },
    { id: 'b', label: 'Action B', separatorBefore: true, onSelect: onB },
  ]
}

describe('DropdownMenu', () => {
  it('is closed until the trigger is clicked', () => {
    render(<DropdownMenu label="YAML" items={items()} />)
    expect(screen.queryByRole('menu')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    expect(screen.getByRole('menu')).toBeDefined()
    expect(screen.getByRole('menuitem', { name: /Action A/ })).toBeDefined()
  })

  it('runs an item and closes on select', () => {
    const onA = vi.fn()
    render(<DropdownMenu label="YAML" items={items(onA)} />)
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Action A/ }))
    expect(onA).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('closes on Escape', () => {
    render(<DropdownMenu label="YAML" items={items()} />)
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('closes on an outside click', () => {
    render(<DropdownMenu label="YAML" items={items()} />)
    fireEvent.click(screen.getByRole('button', { name: /YAML/ }))
    fireEvent.mouseDown(document.body)
    expect(screen.queryByRole('menu')).toBeNull()
  })
})
