import { describe, expect, it } from 'vitest'
import { phaseVariant } from './registry'

describe('phaseVariant', () => {
  it('maps healthy phases to success', () => {
    for (const p of ['Ready', 'Healthy', 'Running', 'Active', 'Available', 'Bound', 'Succeeded']) {
      expect(phaseVariant(p)).toBe('success')
    }
  })

  it('maps in-flight phases to warning', () => {
    for (const p of ['Pending', 'Progressing', 'Degraded', 'Provisioning', 'Updating', 'Unknown']) {
      expect(phaseVariant(p)).toBe('warning')
    }
  })

  it('maps failures to danger', () => {
    for (const p of ['Failed', 'Error', 'CrashLoopBackOff', 'Lost', 'Terminated', 'Evicted']) {
      expect(phaseVariant(p)).toBe('danger')
    }
  })

  it('never renders a negated positive as healthy (the regression class)', () => {
    for (const p of [
      'NotReady',
      'Not Ready',
      'Not-Ready',
      'not_ready',
      'Not Healthy',
      'Unhealthy',
      'Unready',
      'NodeNotReady',
      'KubeletNotReady',
    ]) {
      expect(phaseVariant(p)).toBe('danger')
    }
  })

  it('falls back to neutral for empty/unrecognized phases', () => {
    expect(phaseVariant('')).toBe('neutral')
    expect(phaseVariant(undefined)).toBe('neutral')
    expect(phaseVariant('Suspended')).toBe('neutral')
  })
})
