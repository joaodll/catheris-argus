import { describe, expect, it } from 'vitest'
import { frameworkName, frameworkShortName, frameworkToQuery, listToQuery, parseFramework, parseList, scoreChange, scoreText } from './compliance'

describe('the Compliance list in the URL', () => {
  it('leaves the defaults out and reads them back', () => {
    const state = parseList({})
    expect(state).toEqual({ q: '', provider: [], connection: 0, order: 'score_asc', page: 1 })
    expect(listToQuery(state)).toEqual({ q: undefined, provider: undefined, connection: undefined, order: undefined, page: undefined })
  })

  it('round-trips a search, providers, a connection, an order and a page', () => {
    const state = { q: 'cis', provider: ['aws' as const, 'gcp' as const], connection: 3, order: 'name_desc' as const, page: 2 }
    const query = listToQuery(state)
    expect(query).toEqual({ q: 'cis', provider: ['aws', 'gcp'], connection: '3', order: 'name_desc', page: '2' })
    expect(parseList(query as Record<string, string>)).toEqual(state)
  })

  it('ignores values it does not know', () => {
    expect(parseList({ order: 'severity', connection: '-1', page: 'x', provider: 'azure' })).toEqual({ q: '', provider: [], connection: 0, order: 'score_asc', page: 1 })
  })

  it('reads one provider or several, once each, in display order', () => {
    expect(parseList({ provider: 'aws' }).provider).toEqual(['aws'])
    expect(parseList({ provider: ['oci', 'aws', 'oci'] }).provider).toEqual(['aws', 'oci'])
  })
})

describe('a framework page in the URL', () => {
  it('round-trips every choice', () => {
    const state = { connection: 7, range: '1M' as const, status: 'FAIL' as const, q: '1.1', page: 3, apage: 2 }
    expect(parseFramework(frameworkToQuery(state) as Record<string, string>)).toEqual(state)
  })

  it('falls back to 6M and every status', () => {
    expect(parseFramework({ range: '2Y', status: 'BROKEN' })).toMatchObject({ range: '6M', status: null })
    expect(frameworkToQuery(parseFramework({}))).toEqual({
      connection: undefined,
      range: undefined,
      status: undefined,
      q: undefined,
      page: undefined,
      apage: undefined,
    })
  })
})

describe('how a score reads', () => {
  it('never shows a missing score as 0', () => {
    expect(scoreText(null)).toBe('Not assessed')
    expect(scoreText(0)).toBe('0.0 %')
    expect(scoreText(71.44)).toBe('71.4 %')
  })

  it('reads a higher score as better', () => {
    expect(scoreChange(7.24)).toMatchObject({ text: '▲ +7.2', color: 'var(--delta-better)' })
    expect(scoreChange(-3)).toMatchObject({ text: '▼ −3', color: 'var(--delta-worse)' })
    expect(scoreChange(0.04)).toMatchObject({ text: '±0', color: 'var(--delta-flat)' })
    expect(scoreChange(null).text).toBe('—')
  })

  it("names a framework by Prowler's name, else its key", () => {
    expect(frameworkName({ name: 'CIS AWS Foundations Benchmark v6.0.0', framework: 'cis_6.0_aws' })).toBe('CIS AWS Foundations Benchmark v6.0.0')
    expect(frameworkName({ name: null, framework: 'cis_6.0_aws' })).toBe('cis_6.0_aws')
  })
})

describe("a framework's short name", () => {
  it('is the family and version, or the full name without a family', () => {
    expect(frameworkShortName({ framework: 'cis_6.0_aws', family: 'CIS', version: '6.0', name: 'CIS Amazon Web Services Foundations Benchmark v6.0.0' })).toBe('CIS 6.0')
    expect(frameworkShortName({ framework: 'nist_800_53_revision_5_aws', family: 'NIST-800-53-Revision-5', version: '' })).toBe('NIST 800 53 Revision 5')
    expect(frameworkShortName({ framework: 'soc2_aws', family: null, version: '', name: 'SOC 2' })).toBe('SOC 2')
    expect(frameworkShortName({ framework: 'soc2_aws', family: null, name: null })).toBe('soc2_aws')
  })
})
