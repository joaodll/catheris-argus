import { describe, expect, it } from 'vitest'
import { chosenLayers, graphParams, mapQueryToUrl, parseMapQuery } from './mapQuery'

describe('Map state in the URL', () => {
  it('starts with the defaults and leaves them out of the URL', () => {
    const state = parseMapQuery({})
    expect(state).toEqual({
      focus: null,
      depth: 1,
      layers: ['traffic', 'identity', 'network', 'policy'],
      view: 'map',
      open: null,
      connection: null,
      type: null,
      page: 1,
      tab: 'overview',
      mode: 'resource',
      route: null,
      target: 1,
      step: 1,
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

  it('keeps the view mode: Security in the URL, Infrastructure the default left out', () => {
    expect(parseMapQuery({ mode: 'security' }).mode).toBe('security')
    expect(parseMapQuery({ mode: 'infrastructure' }).mode).toBe('resource')
    expect(parseMapQuery({ mode: 'other' }).mode).toBe('resource')
    expect(mapQueryToUrl(parseMapQuery({ mode: 'security', focus: 'x' }))).toMatchObject({ mode: 'security', focus: 'x' })
    expect(mapQueryToUrl(parseMapQuery({ focus: 'x' })).mode).toBeUndefined()
  })

  it('opens the Attack Path view only with a route, and drops the route in the other views', () => {
    const state = parseMapQuery({ mode: 'attack', route: '12', target: '3', step: '4', focus: 'x' })
    expect(state).toMatchObject({ mode: 'attack', route: 12, target: 3, step: 4 })
    expect(mapQueryToUrl(state)).toMatchObject({ mode: 'attack', route: '12', target: '3', step: '4', focus: 'x' })
    const first = mapQueryToUrl({ ...state, target: 1, step: 1 })
    expect([first.target, first.step]).toEqual([undefined, undefined])
    // No readable route: the Security view.
    expect(parseMapQuery({ mode: 'attack' })).toMatchObject({ mode: 'security', route: null })
    expect(parseMapQuery({ mode: 'attack', route: 'x' }).mode).toBe('security')
    // The Infrastructure view ignores ?route=.
    expect(parseMapQuery({ route: '12', step: '2' })).toMatchObject({ mode: 'resource', route: null, step: 1 })
    const security = mapQueryToUrl({ ...state, mode: 'security' })
    expect(security.mode).toBe('security')
    expect(security).not.toHaveProperty('route')
    expect(security).not.toHaveProperty('step')
  })

  it('ignores a type or a page it cannot use', () => {
    expect(parseMapQuery({ type: 'x'.repeat(129), page: '-2' })).toMatchObject({ type: null, page: 1 })
    expect(parseMapQuery({ type: 'aws_s3_bucket', page: 'two' }).page).toBe(1)
  })

  it('round-trips a full view, in a stable order', () => {
    const query = {
      focus: 'arn:aws:lambda:us-east-1:1:function:api',
      layer: ['network', 'traffic'],
      view: 'list',
      open: 'internet',
    }
    const state = parseMapQuery(query)
    expect(state.layers).toEqual(['traffic', 'network'])
    expect(mapQueryToUrl(state)).toMatchObject({ ...query, layer: ['traffic', 'network'] })
  })

  it('ignores values it does not know', () => {
    const state = parseMapQuery({ layer: 'everything', origin: 'probe', view: 'graph', focus: 'x'.repeat(3000) })
    expect(state).toMatchObject({ layers: ['traffic', 'identity', 'network', 'policy'], view: 'map', focus: null })
    // Sources is gone (owner, 2026-11-14): an old link's ?origin= is ignored and never written.
    expect('origin' in mapQueryToUrl(parseMapQuery({ origin: 'cloudfox' }))).toBe(false)
  })

  it("keeps the panel's tab, leaves Overview out and ignores an unknown one", () => {
    expect(parseMapQuery({ tab: 'problems' }).tab).toBe('problems')
    expect(mapQueryToUrl(parseMapQuery({ tab: 'problems' })).tab).toBe('problems')
    expect(mapQueryToUrl(parseMapQuery({ tab: 'overview' })).tab).toBeUndefined()
    expect(parseMapQuery({ tab: 'summary' }).tab).toBe('overview')
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
    expect(graphParams(state, 'b')).toEqual({ focus: 'b', depth: 2, layer: ['traffic', 'identity', 'network', 'policy'], connection_id: undefined })
    expect(graphParams({ ...state, connection: 4 }, 'b').connection_id).toBe(4)
    expect(graphParams({ ...state, connection: 4 }, 'b', { connection: 7 }).connection_id).toBe(7)
    // Expand reads one hop, whatever the depth.
    expect(graphParams(state, 'b', { depth: 1 }).depth).toBe(1)
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
