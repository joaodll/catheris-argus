import { describe, expect, it } from 'vitest'
import { chosenLayers, graphParams, mapQueryToUrl, parseMapQuery } from './mapQuery'

describe('Map state in the URL', () => {
  it('starts with the defaults and leaves them out of the URL', () => {
    const state = parseMapQuery({})
    expect(state).toEqual({
      focus: null,
      depth: 1,
      layers: ['traffic', 'identity'],
      origins: ['rule', 'cloudfox'],
      view: 'map',
      open: null,
      connection: null,
      type: null,
      page: 1,
    })
    expect(Object.values(mapQueryToUrl(state)).filter((v) => v !== undefined)).toEqual([])
  })

  it('keeps the start screen\'s type and page, and drops a page with no type', () => {
    const state = parseMapQuery({ type: 'aws_s3_bucket', page: '3' })
    expect(state).toMatchObject({ type: 'aws_s3_bucket', page: 3 })
    expect(mapQueryToUrl(state)).toMatchObject({ type: 'aws_s3_bucket', page: '3' })
    expect(mapQueryToUrl({ ...state, page: 1 }).page).toBeUndefined()
    expect(mapQueryToUrl({ ...state, type: null }).page).toBeUndefined()
  })

  it('ignores a type or a page it cannot use', () => {
    expect(parseMapQuery({ type: 'x'.repeat(129), page: '-2' })).toMatchObject({ type: null, page: 1 })
    expect(parseMapQuery({ type: 'aws_s3_bucket', page: 'two' }).page).toBe(1)
  })

  it('round-trips a full view, in a stable order', () => {
    const query = {
      focus: 'arn:aws:lambda:us-east-1:1:function:api',
      layer: ['network', 'traffic'],
      origin: 'cloudfox',
      view: 'list',
      open: 'internet',
    }
    const state = parseMapQuery(query)
    expect(state.layers).toEqual(['traffic', 'network'])
    expect(mapQueryToUrl(state)).toMatchObject({ ...query, layer: ['traffic', 'network'], origin: ['cloudfox'] })
  })

  it('ignores values it does not know', () => {
    const state = parseMapQuery({ layer: 'everything', origin: 'probe', view: 'graph', focus: 'x'.repeat(3000) })
    expect(state).toMatchObject({ layers: ['traffic', 'identity'], origins: ['rule', 'cloudfox'], view: 'map', focus: null })
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
    expect(graphParams(state, 'b')).toEqual({ focus: 'b', depth: 2, map: 'resource', layer: ['traffic', 'identity'], origin: ['rule', 'cloudfox'], connection_id: undefined })
    expect(graphParams({ ...state, connection: 4 }, 'b').connection_id).toBe(4)
    expect(graphParams({ ...state, connection: 4 }, 'b', { connection: 7 }).connection_id).toBe(7)
    // Expand reads one hop, whatever the depth.
    expect(graphParams(state, 'b', { depth: 1 }).depth).toBe(1)
    expect(graphParams(state, 'b', { map: 'security' }).map).toBe('security')
  })

  it('keeps a depth of 1 to 3, and leaves 1 out of the URL', () => {
    expect(parseMapQuery({ depth: '3' }).depth).toBe(3)
    expect(mapQueryToUrl(parseMapQuery({ depth: '3' })).depth).toBe('3')
    expect(mapQueryToUrl(parseMapQuery({ depth: '1' })).depth).toBeUndefined()
    for (const bad of ['0', '4', 'two', '-1']) expect(parseMapQuery({ depth: bad }).depth).toBe(1)
  })

  it("ignores what the first map's links carried: a path, a highlight, front doors and Flow", () => {
    const old = parseMapQuery({ flow: '7', reach: ['open'], region: 'us-east-1', q: 's3', page: '3', path: '42', highlight: 'exploits', connection: '2' })
    expect(old).toEqual({ ...parseMapQuery({}), connection: 2 }) // the start, in that account
    expect(Object.keys(mapQueryToUrl(old)).filter((k) => mapQueryToUrl(old)[k] !== undefined)).toEqual(['connection'])
    expect(parseMapQuery({ flow: '7', focus: 'arn:x' }).focus).toBe('arn:x')
  })
})
