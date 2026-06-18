// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { Field, FormSection, SegField, SelectField, TextField } from './form'

afterEach(cleanup)

describe('form primitives', () => {
  it('FormSection renders a step badge, title and body', () => {
    render(
      <FormSection step="01" title="Identity" sub="who">
        <div>body</div>
      </FormSection>,
    )
    expect(screen.getByText('01')).toBeDefined()
    expect(screen.getByText('Identity')).toBeDefined()
    expect(screen.getByText('body')).toBeDefined()
  })

  it('Field shows the hint, and replaces it with the error when present', () => {
    const { rerender } = render(
      <Field label="Name" hint="a hint">
        <input aria-label="x" />
      </Field>,
    )
    expect(screen.getByText('a hint')).toBeDefined()
    rerender(
      <Field label="Name" hint="a hint" error="bad">
        <input aria-label="x" />
      </Field>,
    )
    expect(screen.getByText('bad')).toBeDefined()
    expect(screen.queryByText('a hint')).toBeNull()
  })

  it('TextField is read-only and reports its value when disabled', () => {
    render(<TextField value="locked" disabled onChange={vi.fn()} />)
    expect((screen.getByRole('textbox') as HTMLInputElement).disabled).toBe(true)
  })

  it('SegField highlights the active option and reports a change', () => {
    const onChange = vi.fn()
    render(<SegField value="HTTP" options={['HTTP', 'HTTPS']} onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'HTTPS' }))
    expect(onChange).toHaveBeenCalledWith('HTTPS')
  })

  it('SelectField reports the chosen option', () => {
    const onChange = vi.fn()
    render(<SelectField value="a" options={[{ value: 'a' }, { value: 'b' }]} onChange={onChange} />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'b' } })
    expect(onChange).toHaveBeenCalledWith('b')
  })
})
