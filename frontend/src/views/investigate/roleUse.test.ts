import { describe, expect, it } from 'vitest'
import { lastUsedText, roleUseLine, roleUseTitle, workloadsText, type RoleUse } from './roleUse'

const used: RoleUse = {
  last_used_at: '2026-10-02T09:30:00+00:00',
  last_used_region: 'us-east-1',
  observed_on: '2026-10-03',
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
})
