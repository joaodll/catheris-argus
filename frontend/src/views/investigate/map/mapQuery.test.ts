import { describe, expect, it } from 'vitest'
import { chosenLayers, graphParams, mapQueryToUrl, parseMapQuery } from './mapQuery'

describe('Resource map state in the URL', () => {
  it('starts with the defaults and leaves them out of the URL', () => {
    const state = parseMapQuery({})
    expect(state).toEqual({
      focus: null,
      depth: 1,
      layers: ['traffic', 'identity'],
      origins: ['rule', 'cloudfox'],
      highlight: null,
      view: 'map',
      path: null,
      open: null,
      connection: null,
    })
    expect(Object.values(mapQueryToUrl(state)).filter((v) => v !== undefined)).toEqual([])
  })

  it('round-trips a full view, in a stable order', () => {
    const query = {
      focus: 'arn:aws:lambda:us-east-1:1:function:api',
      depth: '3',
      layer: ['network', 'traffic'],
      origin: 'cloudfox',
      highlight: 'exploits',
      view: 'list',
      path: '42',
      open: 'internet',
    }
    const state = parseMapQuery(query)
    expect(state.layers).toEqual(['traffic', 'network'])
    expect(mapQueryToUrl(state)).toMatchObject({ ...query, layer: ['traffic', 'network'], origin: ['cloudfox'] })
  })

  it('ignores values it does not know', () => {
    const state = parseMapQuery({ depth: '9', layer: 'everything', origin: 'probe', highlight: 'everything', view: 'graph', path: '-1', focus: 'x'.repeat(3000) })
    expect(state).toMatchObject({ depth: 1, layers: ['traffic', 'identity'], origins: ['rule', 'cloudfox'], highlight: null, view: 'map', path: null, focus: null })
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
    const state = parseMapQuery({ focus: 'a', depth: '2', as_of: '2026-10-01' }) // an older link's day means nothing now
    expect(graphParams(state, 'b', 1)).toEqual({ focus: 'b', depth: 1, layer: ['traffic', 'identity'], origin: ['rule', 'cloudfox'], connection_id: undefined })
    expect(graphParams({ ...state, connection: 4 }, 'b', 1).connection_id).toBe(4)
    expect(graphParams({ ...state, connection: 4 }, 'b', 1, 7).connection_id).toBe(7)
  })

  it('ignores the front doors and Flow of an older link (round M3a)', () => {
    const old = parseMapQuery({ flow: '7', reach: ['open'], region: 'us-east-1', q: 's3', page: '3', mode: 'flow', connection: '2' })
    expect(old).toEqual({ ...parseMapQuery({}), connection: 2 }) // the start, in that account
    expect(Object.keys(mapQueryToUrl(old)).filter((k) => mapQueryToUrl(old)[k] !== undefined)).toEqual(['connection'])
    expect(parseMapQuery({ flow: '7', focus: 'arn:x' }).focus).toBe('arn:x')
  })
})
