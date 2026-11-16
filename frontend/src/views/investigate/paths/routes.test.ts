import { describe, expect, it } from 'vitest'
import { CLASS_LABEL, LEVEL_LABEL, ROUTE_CLASSES, STEP_LEVELS } from './routeClass'
import { isRouteFiltered, parseRouteFilters, parseRouteOrder, parseTarget, routeApiFilters, routeFiltersToQuery } from './routeFilters'
import { REASON, breakLink, chainItems, crossesLine, moveWords, nodeLabel, reasonLine, routeSubline, routeTitle, type Names, type StepOut } from './routeWords'

const names: Names = {
  connection: (id) => ({ 1: 'demo-prod', 2: 'demo-shared', 3: 'demo-data', 4: 'demo-dev' })[id] ?? `Connection ${id}`,
  ofAccount: (account) => (account === '100000000010' ? 'demo-prod' : null),
}

function node(uid: string, extra: Partial<StepOut['source']> = {}): StepOut['source'] {
  const kind = uid === 'internet' ? 'internet' : uid.startsWith('admin:') ? 'admin' : uid.startsWith('any:') ? 'any' : 'resource'
  return { uid, kind, resource_id: kind === 'resource' ? 7 : null, type: null, name: null, connection_id: kind === 'resource' ? 1 : null, deleted_on: null, facts: null, ...extra }
}

function step(n: number, type: string, source: string, target: string, extra: Partial<StepOut> = {}): StepOut {
  return { n, type, source: node(source), target: node(target), edge_id: null, origin: 'rule:x@1', connection_id: 1, day: '2026-11-15', level: 'supported', reason: 'configuration', ref: '', attributes: {}, ...extra }
}

describe('two vocabularies, never the same word', () => {
  it('a route class and a step level share no word', () => {
    const classes = new Set(ROUTE_CLASSES.map((c) => CLASS_LABEL[c]))
    expect(STEP_LEVELS.map((l) => LEVEL_LABEL[l]).filter((w) => classes.has(w))).toEqual([])
    expect(CLASS_LABEL.blocked).toBe('Latent')
    expect(CLASS_LABEL.unknown).toBe('Not enough data')
  })
})

describe('every reason key the walk writes has words', () => {
  // levels.py, walk.py and routes.py, as of R1 (4791c63).
  const KEYS = [
    'internet_rule', 'internet_cloudfox', 'internet_unknown', 'anyone', 'outsider', 'credential',
    'cloudfox_analysis', 'admin_policy', 'trust', 'trust_condition', 'trust_external_id', 'cross_account_trust',
    'account_admin', 'account_identity', 'cross_account_admin', 'cross_account_identity', 'escalation',
    'configuration', 'api_integration', 'manual', 'lateral', 'ssm', 'resource_side_unevaluated', 'trigger_input',
    'trigger_public_write', 'compromise_imdsv1', 'compromise_assumed', 'data_auth_assumed',
  ]
  it.each(KEYS)('%s', (key) => {
    expect(REASON[key]).toBeTruthy()
  })

  it('a CVE foothold names its CVE, a closed door its control, an unknown key its level', () => {
    expect(reasonLine({ reason: 'compromise_cve', level: 'candidate', ref: 'CVE-2026-1234' })).toBe('A public exploit: CVE-2026-1234.')
    expect(reasonLine({ reason: 'compromise_cve', level: 'candidate', ref: '<b>x</b>' })).toBe('A public exploit.')
    expect(reasonLine({ reason: 'internet_restricted:nacl_blocks', level: 'blocked', ref: '' })).toContain('(network ACL)')
    expect(reasonLine({ reason: 'internet_restricted:control', level: 'blocked', ref: '' })).toContain('(a control)')
    expect(reasonLine({ reason: 'something_new', level: 'unknown', ref: '' })).toBe('Argus lacks the data to judge this step.')
  })
})

describe('names and titles', () => {
  it('names pseudo-nodes in words, the walk-scoped ones without their scope', () => {
    expect(nodeLabel(node('admin:100000000010'), names).name).toBe('Administrator of demo-prod')
    expect(nodeLabel(node('admin:210987654321'), names).name).toBe('Administrator of account 210987654321')
    expect(nodeLabel(node('any:dynamodb@1'), names)).toEqual({ type: 'Wildcard grant (*)', name: 'Every dynamodb resource' })
    expect(nodeLabel(node('any:ssm@3'), names).name).toBe('Instances it manages')
    expect(nodeLabel(node('internet'), names).name).toBe('Internet')
    expect(nodeLabel(node('arn:aws:iam::210987654321:root', { resource_id: null }), names).name).toBe('Account 210987654321')
  })

  it('titles a row "<Kind name>: <entry>", and a kind with no file by its id', () => {
    const entry = node('arn:aws:lambda:us-east-1:1:function:orders', { name: 'orders' })
    expect(routeTitle({ kind: 'internet-to-admin', kind_name: 'From the internet to administrator', entry }, names)).toBe('From the internet to administrator: orders')
    expect(routeTitle({ kind: 'gone-kind', kind_name: null, entry }, names)).toBe('Route kind gone-kind: orders')
  })

  it('says the worst target, how many and how many other accounts', () => {
    const worst = node('arn:aws:s3:::exports', { name: 'exports', connection_id: 3 })
    expect(routeSubline({ worst_target: worst, target_count: 14, crossed_connection_ids: [1, 3, 2] }, names)).toBe('Worst: exports in demo-data · 14 targets · crosses 2 other accounts')
    expect(routeSubline({ worst_target: worst, target_count: 1, crossed_connection_ids: [3] }, names)).toBe('To exports in demo-data')
    expect(routeSubline({ worst_target: node('admin:100000000010'), target_count: 1, crossed_connection_ids: [1] }, names)).toBe('To Administrator of demo-prod')
    expect(routeSubline({ worst_target: node('any:dynamodb@3'), target_count: 1, crossed_connection_ids: [1, 3] }, names)).toBe('To Every dynamodb resource in demo-data · crosses 1 other account')
  })

  it('lists at most two crossed accounts, then a count', () => {
    expect(crossesLine({ connection_id: 1, crossed_connection_ids: [1] }, names)).toBeNull()
    expect(crossesLine({ connection_id: 1, crossed_connection_ids: [1, 2, 3, 4] }, names)).toEqual({
      text: '+ crosses demo-shared, demo-data +1',
      title: 'Crosses demo-shared, demo-data and demo-dev',
    })
  })
})

describe('the chain', () => {
  it('puts a foothold on the resource it takes, in walk order', () => {
    const api = 'arn:aws:apigateway:us-east-1::/apis/a'
    const fn = 'arn:aws:lambda:us-east-1:1:function:f'
    const role = 'arn:aws:iam::1:role/r'
    const steps = [
      step(1, 'ROUTES_TO', 'internet', api, { level: 'confirmed', reason: 'internet_rule' }),
      step(2, 'ROUTES_TO', api, fn),
      step(3, 'FOOTHOLD', fn, fn, { origin: 'walk', level: 'candidate', reason: 'compromise_assumed' }),
      step(4, 'RUNS_AS', fn, role),
    ]
    expect(chainItems(steps).map((i) => (i.kind === 'node' ? i.node.uid : `${i.kind}:${i.step.n}`))).toEqual(['internet', 'link:1', api, 'link:2', fn, 'self:3', 'link:4', role])
  })

  it('words a move and how to break it', () => {
    const door = step(1, 'ROUTES_TO', 'internet', 'arn:aws:ec2:1:instance/i', { attributes: { open: ['tcp/22', 'tcp/443'] } })
    expect(moveWords(door).short).toBe('reaches it on tcp/22 (SSH) and tcp/443 (HTTPS)')
    expect(breakLink(door)).toContain('Remove public access')
    const closed = step(1, 'PUBLIC_RESTRICTED', 'internet', 'arn:aws:ec2:1:instance/i', { attributes: { reason: 'sg_no_public_source' } })
    expect(moveWords(closed).short).toBe('kept out: security groups')
    expect(breakLink(step(3, 'FOOTHOLD', 'x', 'x'))).toContain('IMDSv2')
  })
})

describe('Attack paths filters in the URL', () => {
  it('round-trips the filters and leaves defaults out', () => {
    const query = { severity: ['critical', 'high'], kind: ['internet-to-admin'], confidence: ['blocked'], connection: '3', crossing: '1', state: 'fixed', through: '42' }
    const f = parseRouteFilters(query)
    expect(routeFiltersToQuery(f)).toEqual(query)
    expect(isRouteFiltered(parseRouteFilters({}))).toBe(false)
    expect(routeApiFilters(f)).toMatchObject({ cls: ['blocked'], state: 'resolved', through: 42, connection_id: 3, crossing: true })
  })

  it('ignores what it does not know', () => {
    const f = parseRouteFilters({ severity: ['urgent', 'low'], kind: ['Bad Kind', 'internet-to-data'], confidence: ['sure', 'unknown'], connection: 'x', crossing: '1', state: 'gone', through: '-4' })
    expect(f).toEqual({ severity: ['low'], kind: ['internet-to-data'], confidence: ['unknown'], connection: null, crossing: false, state: 'open', through: null })
    expect(parseRouteOrder({ order: 'first_seen_asc' })).toBe('severity')
    expect(parseTarget({ target: '0' })).toBe(1)
    expect(parseTarget({ target: '3' })).toBe(3)
  })
})
