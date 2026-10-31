import { describe, expect, it } from 'vitest'
import { attackPaths, failedFindings, framework, resources, threatScore } from './drill'

const defined = (q: unknown) => Object.fromEntries(Object.entries(q as Record<string, unknown>).filter(([, v]) => v !== undefined))

describe('Overview drill-downs', () => {
  it('opens Misconfigurations with the filters that reproduce a failed-findings count', () => {
    const to = failedFindings(7, 'high') as { name: string; query: Record<string, unknown> }
    expect(to.name).toBe('misconfigurations')
    expect(defined(to.query)).toEqual({ severity: ['high'], tool: ['prowler'], result: ['FAIL'], muted: 'hide', connection: ['7'] })
    expect(defined((failedFindings(0, 'critical') as { query: object }).query)).not.toHaveProperty('connection')
  })

  it('opens Attack paths by severity or category', () => {
    const top = attackPaths(3, { severity: ['critical', 'high'] }) as { name: string; query: Record<string, unknown> }
    expect(top.name).toBe('attack-paths')
    expect(defined(top.query)).toMatchObject({ severity: ['critical', 'high'], connection: '3' })
    expect(defined((attackPaths(0, { category: 'privesc' }) as { query: object }).query)).toEqual({ category: ['privesc'] })
  })

  it('opens Resources and the ThreatScore framework for the same connection', () => {
    expect(resources(2, 'aws_s3_bucket')).toEqual({ name: 'resources', query: { connection: '2', type: 'aws_s3_bucket' } })
    expect(resources(0)).toEqual({ name: 'resources', query: { connection: undefined, type: undefined } })
    expect(threatScore(0)).toMatchObject({ name: 'framework', params: { framework: 'prowler_threatscore_aws' } })
    expect(framework(4, 'cis_6.0_aws')).toEqual({ name: 'framework', params: { framework: 'cis_6.0_aws' }, query: { connection: '4' } })
  })
})
