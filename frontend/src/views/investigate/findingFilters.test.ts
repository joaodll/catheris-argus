import { describe, expect, it } from 'vitest'
import {
  apiFilters,
  categoryLabel,
  emptyFilters,
  filtersToQuery,
  isFiltered,
  parseFilters,
  parseFinding,
  parseOrder,
  parsePage,
  secondaryCount,
} from './findingFilters'

describe('Findings filters in the URL', () => {
  it('reads repeated parameters and round-trips them', () => {
    const query = {
      severity: ['critical', 'high'],
      connection: ['3', '7'],
      provider: 'aws',
      tool: 'cloudfox',
      category: 'secrets',
      service: ['iam', 'awslambda'],
      type: 'AwsIamRole',
      check: 'cloudfox_public_endpoint',
      reach: ['restricted', 'unknown'],
      region: 'global',
      result: 'MANUAL',
      muted: 'hide',
      new: '1',
      state: 'resolved',
      q: 'bucket',
      resource: '12',
    }
    const f = parseFilters(query)
    expect(f.severity).toEqual(['critical', 'high'])
    expect(f.connection).toEqual([3, 7])
    expect(f.tool).toEqual(['cloudfox'])
    expect(f.new).toBe(true)
    expect(f.resource).toBe(12)
    expect(f.reach).toEqual(['restricted', 'unknown'])
    expect(apiFilters(f).reach).toEqual(['restricted', 'unknown'])
    expect(filtersToQuery(f)).toEqual({
      ...query,
      provider: ['aws'],
      tool: ['cloudfox'],
      category: ['secrets'],
      type: ['AwsIamRole'],
      check: ['cloudfox_public_endpoint'],
      region: ['global'],
      result: ['MANUAL'],
    })
  })

  it('ignores values the page does not know, and leaves defaults out', () => {
    const f = parseFilters({ severity: ['severe', 'low'], tool: 'trivy', provider: ['azure', 'gcp'], result: 'PASS', muted: 'maybe', state: 'closed', connection: ['x', '-1', '4'], reach: ['open', 'not_covered'] })
    expect(f.severity).toEqual(['low'])
    expect(f.tool).toEqual([])
    expect(f.provider).toEqual(['gcp'])
    expect(f.result).toEqual([])
    expect(f.muted).toBe('any')
    expect(f.state).toBe('open')
    expect(f.connection).toEqual([4])
    expect(f.reach).toEqual(['not_covered'])
    expect(Object.values(filtersToQuery(emptyFilters())).every((v) => v === undefined)).toBe(true)
    expect(parseOrder({ order: 'title' })).toBe('severity')
    expect(parseOrder({ order: 'severity_asc' })).toBe('severity_asc')
    expect(parsePage({ page: '0' })).toBe(1)
    expect(parsePage({ page: '3' })).toBe(3)
  })

  it('sends the API its own parameter names', () => {
    const params = apiFilters(parseFilters({ type: 'AwsIamRole', check: 'c1', result: 'FAIL', connection: '2', provider: 'aws' }))
    expect(params).toMatchObject({ provider: ['aws'], resource_type: ['AwsIamRole'], check_id: ['c1'], status: ['FAIL'], connection_id: [2], q: null })
  })

  it('counts the More filters row and knows when anything is set', () => {
    expect(isFiltered(emptyFilters())).toBe(false)
    expect(isFiltered(parseFilters({ state: 'resolved' }))).toBe(true)
    expect(secondaryCount(parseFilters({ severity: 'high' }))).toBe(0)
    expect(secondaryCount(parseFilters({ service: 'iam', muted: 'only', new: '1' }))).toBe(3)
    expect(secondaryCount(parseFilters({ reach: 'restricted' }))).toBe(1)
  })

  it('says a category in words', () => {
    expect(categoryLabel('internet-exposed')).toBe('Internet exposed')
    expect(categoryLabel('privilege-escalation')).toBe('Privilege escalation')
  })

  it('reads one finding\'s own link', () => {
    expect(parseFinding({ finding: '42' })).toBe(42)
    expect(parseFinding({ finding: 'x' })).toBeNull()
    expect(parseFinding({ finding: '-3' })).toBeNull()
    expect(parseFinding({})).toBeNull()
  })
})
