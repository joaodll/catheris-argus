import { describe, expect, it } from 'vitest'
import { deltaColor, duration, elapsed, int, relative, scoreColor, signed } from './format'

describe('format', () => {
  it('never turns a missing value into zero', () => {
    expect(int(null)).toBe('No data')
    expect(int(0)).toBe('0')
  })

  it('signs changes with a true minus', () => {
    expect(signed(12)).toBe('+12')
    expect(signed(-3)).toBe('−3')
    expect(signed(0)).toBe('±0')
  })

  it('colours a change by whether it is good', () => {
    expect(deltaColor(5, false)).toBe('var(--delta-worse)')
    expect(deltaColor(5, true)).toBe('var(--delta-better)')
    expect(deltaColor(null, true)).toBe('var(--delta-flat)')
  })

  it('bands the ThreatScore', () => {
    expect(scoreColor(85)).toBe('var(--score-good)')
    expect(scoreColor(65)).toBe('var(--score-weak)')
    expect(scoreColor(null)).toBe('var(--text-3)')
  })

  it('shows a running time as a clock', () => {
    const start = '2026-10-08T12:00:00Z'
    const at = (s: number) => Date.parse(start) + s * 1000
    expect(elapsed(start, at(75))).toBe('01:15')
    expect(elapsed(start, at(3725))).toBe('1:02:05')
    expect(elapsed(start, at(-5))).toBe('00:00')
    expect(elapsed(null)).toBe('—')
  })

  it('reads durations and ages', () => {
    expect(duration(47)).toBe('47 s')
    expect(duration(192)).toBe('3 min 12 s')
    const now = Date.parse('2026-10-03T12:00:00Z')
    expect(relative('2026-10-03T10:00:00Z', now)).toBe('2 h ago')
  })
})
