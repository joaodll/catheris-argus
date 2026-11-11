import { describe, expect, it } from 'vitest'
import { failedFindings, framework, resources, threatScore, vulnerabilitiesSummary } from './drill'

const defined = (q: unknown) => Object.fromEntries(Object.entries(q as Record<string, unknown>).filter(([, v]) => v !== undefined))

describe('Overview drill-downs', () => {
  it('opens Misconfigurations with the filters that reproduce a failed-findings count', () => {
    const to = failedFindings(7, 'high') as { name: string; query: Record<string, unknown> }
    expect(to.name).toBe('misconfigurations')
    expect(defined(to.query)).toEqual({ severity: ['high'], tool: ['prowler'], result: ['FAIL'], muted: 'hide', connection: ['7'] })
    expect(defined((failedFindings(0, 'critical') as { query: object }).query)).not.toHaveProperty('connection')
  })

  it('opens Resources and the ThreatScore framework for the same connection', () => {
    expect(resources(2, 'aws_s3_bucket')).toMatchObject({ name: 'resources', query: { connection: ['2'], type: ['aws_s3_bucket'], assets: '1', tab: 'list' } })
    expect(resources(0)).toMatchObject({ name: 'resources', query: { connection: undefined, type: undefined, assets: '1', tab: 'list' } })
    expect(threatScore(0)).toMatchObject({ name: 'framework', params: { framework: 'prowler_threatscore_aws' } })
    expect(framework(4, 'cis_6.0_aws')).toEqual({ name: 'framework', params: { framework: 'cis_6.0_aws' }, query: { connection: '4' } })
  })

  it('opens the Vulnerabilities summary for the same connection', () => {
    expect(vulnerabilitiesSummary(3)).toEqual({ name: 'vulnerabilities', query: { tab: 'summary', connection: '3' } })
    expect(vulnerabilitiesSummary(0)).toEqual({ name: 'vulnerabilities', query: { tab: 'summary', connection: undefined } })
  })
})
