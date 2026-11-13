import { describe, expect, it } from 'vitest'
import type { Schemas } from '@/api/client'
import { riskFacts } from './riskFacts'
import { COMBINATION_IDS, emptyRiskFilters, isRiskFiltered, parseRiskFilters, riskApiFilters, riskFiltersToQuery, riskLink } from './riskFilters'

function row(overrides: Partial<Schemas['RiskRow']> = {}): Schemas['RiskRow'] {
  return {
    resource_id: 42,
    name: 'web-1',
    connection_id: 3,
    provider: 'aws',
    resource_type: 'aws_ec2_instance',
    tier: 'critical',
    combinations: ['reachable-exploitable'],
    first_seen: '2026-10-09',
    door_held_since: null,
    door: true,
    admin: false,
    env_secret: false,
    credential_kinds: [],
    exploitable_cves: 2,
    high_cves: 1,
    max_epss: 0.864,
    high_misconfigurations: 0,
    worst_misconfiguration: null,
    ...overrides,
  }
}

describe('riskFacts', () => {
  it('says what made the combination, each fact leading to its list or the panel', () => {
    const facts = riskFacts(row())
    expect(facts.map((f) => f.text)).toEqual([
      "Open to the internet (Argus's rules)",
      '2 CVEs with a public exploit',
      '1 critical or high CVE',
      'EPSS 86%',
    ])
    expect(facts[0]?.panel).toBe('door')
    // The CVE list as Risk counts it: this resource, not suppressed, with a public exploit.
    expect(facts[1]?.to).toEqual({ name: 'vulnerabilities', query: expect.objectContaining({ resource: '42', muted: 'hide', exploit: '1', tab: 'list' }) })
    expect(facts[3]?.to).toBeUndefined()
  })

  it('says an EPSS under 1% is under 1%, not 0%', () => {
    expect(riskFacts(row({ max_epss: 0.001 })).find((f) => f.key === 'epss')?.text).toBe('EPSS <1%')
  })

  it('links misconfigurations open and failing, and the secret to its check', () => {
    const facts = riskFacts(row({ door: false, exploitable_cves: 0, high_cves: 0, max_epss: null, high_misconfigurations: 3, env_secret: true }))
    expect(facts.map((f) => f.text)).toEqual(['3 critical or high misconfigurations', 'Secret in its environment variables (CloudFox)'])
    expect(facts[0]?.to).toEqual({
      name: 'misconfigurations',
      query: expect.objectContaining({ resource: '42', muted: 'hide', result: ['FAIL'], severity: ['critical', 'high'] }),
    })
    expect(facts[1]?.to).toEqual({ name: 'misconfigurations', query: expect.objectContaining({ check: ['cloudfox_env_var_secret'] }) })
  })

  it('names an admin user\'s credentials without calling them leaked', () => {
    const facts = riskFacts(
      row({ door: false, exploitable_cves: 0, high_cves: 0, max_epss: null, admin: true, credential_kinds: ['access_key', 'console_password_no_mfa'] }),
    )
    expect(facts.map((f) => f.text)).toEqual([
      'Admin, or can make itself admin',
      'Signs in from anywhere: an active access key and a console password without MFA',
    ])
    expect(facts.every((f) => f.panel === 'resource')).toBe(true)
  })
})

describe('riskFilters', () => {
  it('reads the URL, ignoring what it does not know', () => {
    const f = parseRiskFilters({ connection: ['7', '9'], tier: ['critical', 'low'], combination: ['reachable-secret', 'nope'], provider: 'gcp', type: 'aws_iam_user' })
    expect(f).toEqual({ connection: 7, tier: ['critical'], combination: ['reachable-secret'], provider: ['gcp'], type: ['aws_iam_user'] })
    expect(riskApiFilters(f)).toEqual({ connection_id: [7], tier: ['critical'], combination: ['reachable-secret'], provider: ['gcp'], type: ['aws_iam_user'] })
  })

  it('writes defaults out of the URL, and the account is not a filter to clear', () => {
    expect(riskFiltersToQuery(emptyRiskFilters())).toEqual({ connection: undefined, provider: undefined, tier: undefined, combination: undefined, type: undefined })
    expect(isRiskFiltered({ ...emptyRiskFilters(), connection: 3 })).toBe(false)
    expect(riskLink({ connection: 3, tier: ['high'] })).toEqual({ name: 'risk', query: expect.objectContaining({ connection: '3', tier: ['high'] }) })
  })

  it('lists every combination the contract names', () => {
    expect(COMBINATION_IDS).toHaveLength(6)
  })
})
