import { describe, expect, it } from 'vitest'
import {
  emptyResourceFilters,
  isResourceFiltered,
  parseResourceFilters,
  parseResourceOrder,
  resourceApiFilters,
  resourceFiltersToQuery,
  resourceSecondaryCount,
  resourcesLink,
} from './resourceFilters'

describe('resource filters and the URL', () => {
  it('reads what it knows and drops the rest', () => {
    const f = parseResourceFilters({
      connection: ['3', 'x', '0'],
      type: ['aws_s3_bucket', ''],
      vulnerabilities: 'bogus',
      misconfigurations: 'high',
      internet: '1',
      assets: 'yes',
      first_seen_from: '2026-13-01',
      removed_to: '2026-11-02',
    })
    expect(f.connection).toEqual([3])
    expect(f.type).toEqual(['aws_s3_bucket'])
    expect(f.vulnerabilities).toBeNull()
    expect(f.misconfigurations).toBe('high')
    expect(f.internet).toBe(true)
    expect(f.assets).toBe(false) // only '1' sets a flag
    expect(f.firstSeenFrom).toBe('') // not a real day
    expect(f.removedTo).toBe('2026-11-02')
  })

  it('keeps up to 200 types, so a service link with all its types reads whole', () => {
    const many = Array.from({ length: 250 }, (_, n) => `aws_ec2_t${n}`)
    expect(parseResourceFilters({ type: many }).type).toHaveLength(200)
    expect(parseResourceFilters({ region: many }).region).toHaveLength(50)
  })

  it('round-trips through the query string, defaults left out', () => {
    const f = { ...emptyResourceFilters(), connection: [2], type: ['aws_ec2_instance'], assets: true, internet: true, removedFrom: '2026-10-01' }
    const query = resourceFiltersToQuery(f)
    expect(query).toMatchObject({ connection: ['2'], type: ['aws_ec2_instance'], assets: '1', internet: '1', removed_from: '2026-10-01' })
    expect(query.deleted).toBeUndefined()
    expect(parseResourceFilters(query as never)).toEqual(f)
    expect(isResourceFiltered(f)).toBe(true)
    expect(isResourceFiltered(emptyResourceFilters())).toBe(false)
  })

  it('sends the API its parameter names', () => {
    const api = resourceApiFilters({ ...emptyResourceFilters(), region: ['global'], removedTo: '2026-11-01', includeDeleted: true })
    expect(api).toMatchObject({ region: ['global'], deleted_to: '2026-11-01', deleted_from: null, include_deleted: true, q: null, misconfigurations: null })
  })

  it('counts each row-2 filter once, a date range as one', () => {
    expect(resourceSecondaryCount(emptyResourceFilters())).toBe(0)
    const f = { ...emptyResourceFilters(), firstSeenFrom: '2026-10-01', firstSeenTo: '2026-10-07', misconfigurations: 'any' as const, includeDeleted: true }
    expect(resourceSecondaryCount(f)).toBe(3)
  })

  it('reads the order, name A to Z by default', () => {
    expect(parseResourceOrder({ order: 'last_seen_desc' })).toBe('last_seen_desc')
    expect(parseResourceOrder({ order: 'nope' })).toBe('name_asc')
  })

  it('links to the list with only the filters given', () => {
    expect(resourcesLink({ assets: true, misconfigurations: 'high' })).toEqual({
      name: 'resources',
      query: expect.objectContaining({ assets: '1', misconfigurations: 'high', tab: 'list', connection: undefined }),
    })
  })
})
