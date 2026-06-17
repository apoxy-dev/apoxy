// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import {
  chordEquals,
  eventChord,
  formatChord,
  formatSequence,
  isEditableTarget,
  isModifierOnly,
  parseChord,
  parseSequence,
  sequenceEquals,
  sequenceStartsWith,
} from './keys'

describe('parseChord', () => {
  it('parses a bare key', () => {
    expect(parseChord('j')).toEqual({ key: 'j', mod: false, shift: false, alt: false })
  })
  it('parses modifiers and aliases', () => {
    expect(parseChord('mod+k')).toEqual({ key: 'k', mod: true, shift: false, alt: false })
    expect(parseChord('cmd+shift+p')).toEqual({ key: 'p', mod: true, shift: true, alt: false })
    expect(parseChord('Ctrl+S')).toEqual({ key: 's', mod: true, shift: false, alt: false })
    expect(parseChord('esc').key).toBe('escape')
    expect(parseChord('up').key).toBe('arrowup')
  })
  it('treats `space` as a literal space key', () => {
    expect(parseChord('space').key).toBe(' ')
  })
})

describe('parseSequence', () => {
  it('splits space-separated chords into a sequence', () => {
    const seq = parseSequence('g i')
    expect(seq).toHaveLength(2)
    expect(seq[0]!.key).toBe('g')
    expect(seq[1]!.key).toBe('i')
  })
  it('keeps a +-joined chord as one element', () => {
    expect(parseSequence('mod+k')).toHaveLength(1)
  })
})

describe('sequence matching', () => {
  const gi = parseSequence('g i')
  it('startsWith detects a proper prefix', () => {
    expect(sequenceStartsWith(gi, parseSequence('g'))).toBe(true)
    expect(sequenceStartsWith(gi, parseSequence('i'))).toBe(false)
    expect(sequenceStartsWith(gi, parseSequence('g i'))).toBe(true)
  })
  it('equals requires identical length and chords', () => {
    expect(sequenceEquals(gi, parseSequence('g i'))).toBe(true)
    expect(sequenceEquals(gi, parseSequence('g'))).toBe(false)
  })
})

describe('eventChord', () => {
  it('reads ⌘ as mod on mac and Ctrl elsewhere', () => {
    const meta = new KeyboardEvent('keydown', { key: 'k', metaKey: true })
    expect(eventChord(meta, true)).toEqual({ key: 'k', mod: true, shift: false, alt: false })
    expect(eventChord(meta, false).mod).toBe(false)

    const ctrl = new KeyboardEvent('keydown', { key: 'k', ctrlKey: true })
    expect(eventChord(ctrl, false).mod).toBe(true)
    expect(eventChord(ctrl, true).mod).toBe(false)
  })
  it('lowercases the key', () => {
    expect(eventChord(new KeyboardEvent('keydown', { key: 'J' }), false).key).toBe('j')
  })
})

describe('isModifierOnly', () => {
  it('flags a bare modifier press', () => {
    expect(isModifierOnly(parseChord('shift'))).toBe(true)
    expect(isModifierOnly({ key: '', mod: true, shift: false, alt: false })).toBe(true)
    expect(isModifierOnly(parseChord('k'))).toBe(false)
  })
})

describe('isEditableTarget', () => {
  it('detects inputs, textareas and contenteditable', () => {
    const input = document.createElement('input')
    const textarea = document.createElement('textarea')
    const div = document.createElement('div')
    expect(isEditableTarget(input)).toBe(true)
    expect(isEditableTarget(textarea)).toBe(true)
    expect(isEditableTarget(div)).toBe(false)
    expect(isEditableTarget(null)).toBe(false)
  })
})

describe('formatting', () => {
  it('renders mac glyphs and cross-platform fallbacks', () => {
    expect(formatChord(parseChord('mod+k'), true)).toBe('⌘K')
    expect(formatChord(parseChord('mod+k'), false)).toBe('Ctrl+K')
    expect(formatChord(parseChord('escape'), true)).toBe('Esc')
    expect(formatSequence(parseSequence('g i'), true)).toBe('G then I')
  })
})

describe('chordEquals', () => {
  it('compares all fields', () => {
    expect(chordEquals(parseChord('mod+k'), parseChord('mod+k'))).toBe(true)
    expect(chordEquals(parseChord('mod+k'), parseChord('k'))).toBe(false)
  })
})
