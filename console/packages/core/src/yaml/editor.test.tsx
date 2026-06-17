// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { TextAreaEditor } from './editor'

afterEach(cleanup)

describe('TextAreaEditor', () => {
  it('does not insert a tab or fire onChange when read-only', () => {
    const onChange = vi.fn()
    render(<TextAreaEditor value={'a: 1'} onChange={onChange} readOnly ariaLabel="YAML" />)
    const ta = screen.getByRole('textbox', { name: 'YAML' }) as HTMLTextAreaElement
    // Tab in a read-only editor must neither trap focus (mutate via the native
    // setter) nor fire onChange — it bypasses the readOnly guard otherwise.
    fireEvent.keyDown(ta, { key: 'Tab' })
    expect(onChange).not.toHaveBeenCalled()
    expect(ta.value).toBe('a: 1')
  })
})
