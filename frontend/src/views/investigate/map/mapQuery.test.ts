import { describe, expect, it } from 'vitest'
import { chosenLayers, graphParams, mapQueryToUrl, modeOf, parseMapQuery } from './mapQuery'

describe('Resource map state in the URL', () => {
  it('starts with the defaults and leaves them out of the URL', () => {
    const state = parseMapQuery({})
    expect(state).toEqual({
      flow: null,
      focus: null,
      depth: 1,
      layers: ['traffic', 'identity'],
      origins: ['rule', 'cloudfox'],
      asOf: null,
      view: 'map',
      path: null,
      open: null,
      connection: null,
      q: '',
      reach: [],
      region: [],
      page: 1,
    })
    expect(Object.values(mapQueryToUrl(state)).filter((v) => v !== undefined)).toEqual([])
  })

  it('round-trips a full view, in a stable order', () => {
    const query = {
      focus: 'arn:aws:lambda:us-east-1:1:function:api',
      depth: '3',
      layer: ['network', 'traffic'],
      origin: 'cloudfox',
      as_of: '2026-10-01',
      view: 'list',
      path: '42',
      open: 'internet',
    }
    const state = parseMapQuery(query)
    expect(state.layers).toEqual(['traffic', 'network'])
    expect(mapQueryToUrl(state)).toMatchObject({ ...query, layer: ['traffic', 'network'], origin: ['cloudfox'] })
  })

  it('ignores values it does not know', () => {
    const state = parseMapQuery({ depth: '9', layer: 'everything', origin: 'probe', as_of: 'yesterday', view: 'graph', path: '-1', focus: 'x'.repeat(3000) })
    expect(state).toMatchObject({ depth: 1, layers: ['traffic', 'identity'], origins: ['rule', 'cloudfox'], asOf: null, view: 'map', path: null, focus: null })
  })

  it('defaults to the List view on a phone, and keeps a chosen Map', () => {
    expect(parseMapQuery({}, 'list').view).toBe('list')
    expect(mapQueryToUrl(parseMapQuery({ view: 'map' }, 'list'), 'list').view).toBe('map')
  })

  it('reads nothing chosen in Layers as every layer', () => {
    expect(chosenLayers([])).toEqual(['traffic', 'identity', 'network', 'policy', 'data'])
    expect(chosenLayers(['policy', 'traffic'])).toEqual(['traffic', 'policy'])
  })

  it('builds the graph request for a focus', () => {
    const state = parseMapQuery({ focus: 'a', depth: '2', as_of: '2026-10-01' })
    expect(graphParams(state, 'b', 1)).toEqual({ focus: 'b', depth: 1, layer: ['traffic', 'identity'], origin: ['rule', 'cloudfox'], as_of: '2026-10-01', connection_id: undefined })
    expect(graphParams({ ...state, connection: 4 }, 'b', 1).connection_id).toBe(4)
    expect(graphParams({ ...state, connection: 4 }, 'b', 1, 7).connection_id).toBe(7)
  })

  it('says the mode by what is open: a flow, a focus, or the front doors', () => {
    expect(modeOf(parseMapQuery({}))).toBe('doors')
    expect(modeOf(parseMapQuery({ focus: 'arn:x' }))).toBe('explore')
    expect(modeOf(parseMapQuery({ flow: '7', focus: 'arn:x' }))).toBe('flow')
    // An older link's mode is ignored and never written back.
    expect(modeOf(parseMapQuery({ mode: 'explore' }))).toBe('doors')
    expect(mapQueryToUrl(parseMapQuery({ mode: 'flow', flow: '7' }))).not.toHaveProperty('mode')
  })

  it('keeps the front doors filters and page, in a stable order', () => {
    const state = parseMapQuery({ reach: ['cloudfox_only', 'restricted', 'unknown', 'open', 'nowhere'], region: ['us-east-1', 'eu-west-1', 'x'.repeat(65)], page: '3' })
    const reach = ['open', 'unknown', 'restricted', 'cloudfox_only']
    expect(state).toMatchObject({ reach, region: ['eu-west-1', 'us-east-1'], page: 3 })
    expect(mapQueryToUrl(state)).toMatchObject({ reach, region: ['eu-west-1', 'us-east-1'], page: '3' })
    expect(parseMapQuery({ page: '0' }).page).toBe(1)
    expect(parseMapQuery({ q: '  S3 ' }).q).toBe('S3')
    expect(mapQueryToUrl(parseMapQuery({ q: 's3' })).q).toBe('s3')
    expect(parseMapQuery({ q: 'x'.repeat(250) }).q).toHaveLength(200)
    expect(mapQueryToUrl(parseMapQuery({ page: '1' })).page).toBeUndefined()
  })
})
