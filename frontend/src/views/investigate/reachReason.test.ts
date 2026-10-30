import { describe, expect, it } from 'vitest'
import { hasEvidence, reasonWords, toolNote } from './reachReason'

describe('reasonWords', () => {
  it('puts a door reason in words', () => {
    expect(reasonWords('restricted', 'not_running')).toEqual({ text: 'Not running: nothing listens until it starts.', mono: false })
    expect(reasonWords('restricted', 'nacl_blocks').text).toBe("The subnet's network ACL blocks the internet.")
    expect(reasonWords('unknown', 'inspection_route').text).toContain('firewall endpoint')
  })

  it('says what no door means', () => {
    expect(reasonWords('restricted', 'no_door').text).toContain('found no way in')
    expect(reasonWords('not_covered', 'not_in_inventory').text).toContain('Steampipe has not collected it')
  })

  it('falls back to the reach alone without a reason', () => {
    expect(reasonWords('confirmed', null).text).toBe('Argus found a way in: traffic from the internet can arrive.')
    expect(reasonWords('not_covered', null).text).toBe('No Argus rule checks this kind of resource.')
    expect(reasonWords('unknown', undefined).text).toContain('was not collected')
  })

  it('shows a code it does not know as itself', () => {
    expect(reasonWords('restricted', 'future_reason')).toEqual({ text: 'future_reason', mono: true })
  })
})

describe('toolNote', () => {
  it('explains a disagreement per tool', () => {
    expect(toolNote('prowler', 'restricted')).toContain('Prowler flags an open security group')
    expect(toolNote('cloudfox', 'unknown')).toContain('CloudFox calls an endpoint public')
  })

  it('says nothing when the tools agree or Argus did not judge', () => {
    expect(toolNote('prowler', 'confirmed')).toBeNull()
    expect(toolNote('prowler', 'not_covered')).toBeNull()
  })
})

describe('hasEvidence', () => {
  it('links the evidence only where Argus drew a door', () => {
    expect(hasEvidence('restricted', 'nacl_blocks')).toBe(true)
    expect(hasEvidence('confirmed', null)).toBe(true)
    expect(hasEvidence('restricted', 'no_door')).toBe(false)
    expect(hasEvidence('not_covered', 'not_in_inventory')).toBe(false)
  })
})
