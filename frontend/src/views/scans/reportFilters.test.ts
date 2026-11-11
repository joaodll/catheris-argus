import { describe as group, expect, it } from 'vitest'
import { describe, fromStored } from './reportFilters'

const name = (id: number): string => `account-${id}`

group('a report’s filters in words', () => {
  it('says All open when nothing narrows it', () => {
    expect(describe({}, name)).toBe('All open')
    expect(describe(fromStored({ tools: ['prowler', 'cloudfox'], state: 'open', muted: 'any' }), name)).toBe('All open')
  })

  it('reads the list’s query shape and a stored report the same way', () => {
    const query = { severity: ['critical', 'high'], connection_id: [3], first_seen_from: '2026-10-01', q: 'bucket' }
    const stored = { severities: ['critical', 'high'], connection_ids: [3], first_seen_from: '2026-10-01', q: 'bucket' }
    const words = 'Critical, High · account-3 · first seen from 2026-10-01 · “bucket”'
    expect(describe(query, name)).toBe(words)
    expect(describe(fromStored(stored), name)).toBe(words)
  })

  it('counts several values and names a narrowed tool and state', () => {
    expect(describe({ connection_id: [1, 2], region: ['a', 'b', 'c'], tool: ['cloudfox'], state: 'resolved' }, name)).toBe(
      '2 accounts · CloudFox · Resolved · 3 regions',
    )
    expect(describe({ exploitable: true, fix: 'available' }, name)).toBe('public exploit · fix available')
  })
})
