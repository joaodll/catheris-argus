import { describe, expect, it } from 'vitest'
import { lastUsedText, roleUseLine, roleUseTitle, workloadsText, type RoleUse } from './roleUse'

const used: RoleUse = {
  last_used_at: '2026-10-02T09:30:00+00:00',
  last_used_region: 'us-east-1',
  observed_on: '2026-10-03',
  created_at: '2024-03-01T10:00:00+00:00',
  tracking_days: 400,
  workloads: 2,
}

describe('role use in words', () => {
  it('reads a used role', () => {
    expect(roleUseLine(used)).toEqual(['Last used 2026-10-02', 'us-east-1', '2 workloads'])
    expect(lastUsedText(used)).toBe('2026-10-02 · us-east-1')
    expect(workloadsText(used)).toBe('2 run as it')
    expect(roleUseTitle(used)).toContain('read 2026-10-03')
  })

  it('says AWS records no use in its window, not "never"', () => {
    const idle = { ...used, last_used_at: null, last_used_region: null, workloads: 0 }
    expect(roleUseLine(idle)).toEqual(['Not used in 400 days', 'no workload'])
    expect(lastUsedText(idle)).toBe('Not in the last 400 days')
    expect(workloadsText(idle)).toBe('None')
  })

  it('says what is not collected, never a zero', () => {
    const unread = { ...used, last_used_at: null, last_used_region: null, observed_on: null, workloads: null }
    expect(roleUseLine(unread)).toEqual(['Last use not collected yet', 'workloads not counted yet'])
    expect(lastUsedText(unread)).toBe('Not collected yet')
    expect(workloadsText(unread)).toBe('Not counted yet')
    expect(roleUseTitle(unread)).not.toContain('read')
  })

  it('uses the singular for one workload, and the UTC day', () => {
    const one = { ...used, last_used_at: '2026-10-02T23:30:00-05:00', workloads: 1 }
    expect(roleUseLine(one)).toEqual(['Last used 2026-10-03', 'us-east-1', '1 workload'])
    expect(workloadsText(one)).toBe('1 runs as it')
  })

  it('says a role created inside the window was never used, and an older one not in 400 days', () => {
    const fresh = { ...used, last_used_at: null, last_used_region: null, created_at: '2026-09-20T08:00:00Z', workloads: 0 }
    expect(roleUseLine(fresh)).toEqual(['Never used', 'created 2026-09-20', 'no workload'])
    expect(lastUsedText(fresh)).toBe('Never used · created 2026-09-20')
    // Created 400 days or more before the reading: AWS's window holds, so "not used in 400 days".
    const old = { ...fresh, created_at: '2025-08-29T08:00:00Z' }
    expect(roleUseLine(old)[0]).toBe('Not used in 400 days')
    // Creation not read yet: the window's words, never a guess.
    expect(roleUseLine({ ...fresh, created_at: null })[0]).toBe('Not used in 400 days')
    // A used role is never "never used", whenever it was created.
    expect(roleUseLine({ ...used, created_at: '2026-09-20T08:00:00Z' })[0]).toBe('Last used 2026-10-02')
  })
})
