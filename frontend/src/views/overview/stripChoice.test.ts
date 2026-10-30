import { afterEach, describe, expect, it, vi } from 'vitest'
import { loadStrip, parseStrip, saveStrip } from './stripChoice'

describe("the strip's framework", () => {
  afterEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()
  })

  it('reads a framework key from the URL, and anything else as the ThreatScore', () => {
    expect(parseStrip('cis_6.0_aws')).toBe('cis_6.0_aws')
    expect(parseStrip(['nist_800_53_revision_5_aws', 'x'])).toBe('nist_800_53_revision_5_aws')
    expect(parseStrip(undefined)).toBe('')
    expect(parseStrip('../admin')).toBe('')
    expect(parseStrip('x'.repeat(201))).toBe('')
  })

  it('remembers the last choice in this browser, and forgets the ThreatScore', () => {
    saveStrip('cis_6.0_aws')
    expect(loadStrip()).toBe('cis_6.0_aws')
    saveStrip('')
    expect(loadStrip()).toBe('')
  })

  it('ignores a stored value that is not a key', () => {
    localStorage.setItem('argus.overview.strip', '<script>')
    expect(loadStrip()).toBe('')
  })

  it('works without storage', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    expect(() => saveStrip('cis_6.0_aws')).not.toThrow()
    expect(loadStrip()).toBe('')
  })
})
