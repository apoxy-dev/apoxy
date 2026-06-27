// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { KeyboardScopeProvider } from '../../keyboard/scope-stack'
import { BodyBox } from './body-box'

afterEach(cleanup)

const wrap = (ui: ReactNode) => render(<KeyboardScopeProvider>{ui}</KeyboardScopeProvider>)

const JSON_BODY = '{\n  "model": "claude",\n  "max_tokens": 4096\n}'

describe('BodyBox', () => {
  it('renders the title, one gutter number per line, and the line/byte footer', () => {
    wrap(<BodyBox title="Request body" views={[{ id: 'b', text: JSON_BODY }]} />)
    expect(screen.getByText('Request body')).toBeDefined()
    // Four lines -> gutter numbers 1..4, and a "4 lines" footer.
    expect(screen.getByText('4')).toBeDefined()
    expect(screen.getByText(/^4 lines · /)).toBeDefined()
  })

  it('shows a segmented selector only for multiple views and switches text', () => {
    wrap(
      <BodyBox
        title="Response body"
        contentType="text/event-stream"
        views={[
          { id: 'decoded', label: 'Decoded', text: 'assembled reply' },
          { id: 'raw', label: 'Raw', text: 'event: message_start' },
        ]}
      />,
    )
    expect(screen.getByText('assembled reply')).toBeDefined()
    expect(screen.queryByText('event: message_start')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Raw' }))
    expect(screen.getByText('event: message_start')).toBeDefined()
    expect(screen.getByText('text/event-stream')).toBeDefined()
  })

  it('does not render a selector for a single view', () => {
    wrap(<BodyBox title="Request body" views={[{ id: 'b', label: 'Only', text: 'hi' }]} />)
    expect(screen.queryByRole('button', { name: 'Only' })).toBeNull()
  })

  it('copies the active view text to the clipboard', () => {
    const writeText = vi.fn()
    Object.assign(navigator, { clipboard: { writeText } })
    wrap(<BodyBox title="Request body" views={[{ id: 'b', text: 'payload-xyz' }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    expect(writeText).toHaveBeenCalledWith('payload-xyz')
  })

  it('opens fullscreen, closes via the button, and on Escape', () => {
    wrap(<BodyBox title="Trace body" views={[{ id: 'b', text: 'x' }]} />)
    expect(screen.queryByRole('dialog')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Fullscreen' }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Trace body')).toBeDefined()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('surfaces a truncated capture and its note in the footer', () => {
    wrap(
      <BodyBox
        title="Response body"
        views={[{ id: 'b', text: 'cut', bytes: 65536, truncated: true, note: 'raw event stream' }]}
      />,
    )
    expect(screen.getByText(/truncated/)).toBeDefined()
    expect(screen.getByText(/raw event stream/)).toBeDefined()
  })
})
