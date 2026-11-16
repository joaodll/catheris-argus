import { describe, expect, it } from 'vitest'
import type { StepOut } from '../paths/routeWords'
import { ROUTE_COLUMN, ROUTE_ROW, crossings, leaveFocus, nodeAccount, perRow, routeBend, routeDrawing, routeLayout, stepAnnouncement, stepAtCard, stepRole, type Accounts } from './routeMap'

// Two scanned accounts: connection 1 is 100000000010, connection 2 is 100000000001.
const NAMES: Record<number, string> = { 1: 'demo-prod', 2: 'demo-shared-services-and-tooling' }
const ACCOUNT: Record<number, string> = { 1: '100000000010', 2: '100000000001' }
const accounts: Accounts = {
  accountOf: (id) => ACCOUNT[id] ?? null,
  connectionOf: (account) => Number(Object.keys(ACCOUNT).find((id) => ACCOUNT[Number(id)] === account)) || null,
  name: (id) => NAMES[id] ?? `Connection ${id}`,
}

function node(uid: string, extra: Partial<StepOut['source']> = {}): StepOut['source'] {
  const kind = uid === 'internet' ? 'internet' : uid.startsWith('any:') ? 'any' : uid.startsWith('external:') ? 'external' : uid.startsWith('admin:') ? 'admin' : 'resource'
  return { uid, kind, resource_id: kind === 'resource' ? 7 : null, type: null, name: uid, connection_id: kind === 'resource' ? 1 : null, deleted_on: null, facts: null, ...extra }
}

function step(n: number, type: string, source: StepOut['source'], target: StepOut['target'], extra: Partial<StepOut> = {}): StepOut {
  return { n, type, source, target, edge_id: null, origin: 'rule:x@1', connection_id: 1, day: '2026-11-15', level: 'supported', reason: 'configuration', ref: '', attributes: {}, ...extra }
}

// The internet reaches a load balancer, a foothold on the instance behind it, its role assumes a
// role in another account.
const lb = node('arn:lb')
const web = node('arn:web')
const role = node('arn:role')
const admin = node('arn:admin', { connection_id: 2 })
const steps: StepOut[] = [
  step(1, 'INTERNET_REACHABLE', node('internet'), lb, { origin: 'rule:internet@1', level: 'confirmed', }),
  step(2, 'ROUTES_TO', lb, web, { origin: 'cloudfox' }),
  step(3, 'FOOTHOLD', web, web, { level: 'candidate', reason: 'compromise_assumed' }),
  step(4, 'RUNS_AS', web, role),
  step(5, 'CAN_ASSUME', role, admin, { origin: 'manual', connection_id: 2 }),
]

describe('the two reds', () => {
  it('step 1 from outside is the way in; everything after it is lateral', () => {
    expect(stepRole(steps[0]!)).toBe('entry')
    expect(stepRole(step(1, 'OUTSIDER', node('external:acct'), role))).toBe('entry')
    expect(stepRole(step(1, 'X', node('any:s3'), role))).toBe('entry')
    // A route whose entry is its own resource (a public bucket): no way in drawn from outside.
    expect(stepRole(step(1, 'ROUTES_TO', lb, web))).toBe('lateral')
    expect(steps.slice(1).map(stepRole)).toEqual(['lateral', 'lateral', 'lateral', 'lateral'])
  })
})

describe('the drawing', () => {
  const drawing = routeDrawing(steps, accounts)

  it('has each card once, in walk order', () => {
    expect(drawing.nodes.map((n) => n.uid)).toEqual(['internet', 'arn:lb', 'arn:web', 'arn:role', 'arn:admin'])
  })

  it('draws a line per move, none for a foothold, which gets a tab instead', () => {
    expect(drawing.lines.map((l) => [l.n, l.role, l.style])).toEqual([
      [1, 'entry', 'solid'],
      [2, 'lateral', 'dashed'],
      [4, 'lateral', 'solid'],
      [5, 'lateral', 'dotted'],
    ])
    expect(drawing.selfSteps).toEqual([{ n: 3, on: 'arn:web', tab: 'Foothold · Assumed' }])
  })

  it("says where a line crosses into another account, cutting a long name on the canvas only", () => {
    expect([...crossings(steps, accounts)]).toEqual([[5, 'demo-shared-services-and-tooling']])
    expect(drawing.lines.at(-1)!.words).toBe('can assume · into demo-shared-service…')
    expect(drawing.lines[0]!.words).toBe('reaches it')
  })
})

describe('the player', () => {
  it("reads a crossing from the two ends' accounts, also for a principal not in the inventory", () => {
    // The Demo estate's outsider route: the internet, account 100000000001's root (no
    // resource), a role in 100000000010, its administrator.
    const root = node('arn:aws:iam::100000000001:root', { resource_id: null, connection_id: null })
    const role2 = node('arn:aws:iam::100000000010:role/Org', { connection_id: 1 })
    const outsider = [
      step(1, 'OUTSIDER', node('internet'), root, { connection_id: 2 }),
      step(2, 'CAN_ASSUME', root, role2, { connection_id: 1 }),
      step(3, 'IS_ADMIN', role2, node('admin:100000000010'), { connection_id: 1 }),
    ]
    expect([...crossings(outsider, accounts)]).toEqual([[2, 'demo-prod']])
    const d = routeDrawing(outsider, accounts)
    expect(d.lines.map((l) => l.words)).toEqual(['outsider: another account', 'can assume · into demo-prod', expect.any(String)])
    // The root card takes the connection that scans its account.
    expect(d.nodes[1]!.connection_id).toBe(2)
    // Every resource card names its account; one no connection scans, by its id.
    expect([...d.accounts]).toEqual([
      ['arn:aws:iam::100000000001:root', 'demo-shared-services-and-tooling'],
      ['arn:aws:iam::100000000010:role/Org', 'demo-prod'],
    ])
    const lone = routeDrawing([step(1, 'OUTSIDER', node('internet'), node('arn:aws:iam::999999999999:root', { resource_id: null, connection_id: null }))], accounts)
    expect(lone.accounts.get('arn:aws:iam::999999999999:root')).toBe('account 999999999999')
    expect(nodeAccount(node('admin:100000000010'), accounts)).toBe('100000000010')
    expect(nodeAccount(node('any:dynamodb@2'), accounts)).toBe('100000000001')
    expect(nodeAccount(node('internet'), accounts)).toBeNull()
  })

  it("never reads the step's stored connection, which owns the edge row, not where it lands", () => {
    // A role in connection 1 reads a bucket in connection 2: the edge is the role's policy, owned
    // by connection 1. The move still crosses into the bucket's account.
    const bucket = node('arn:aws:s3:::shared-bucket', { connection_id: 2 })
    expect([...crossings([step(1, 'ACCESSES', role, bucket, { connection_id: 1 })], accounts)]).toEqual([[1, 'demo-shared-services-and-tooling']])
    // An account Argus doesn't scan is named by its id.
    const elsewhere = node('arn:aws:iam::999999999999:role/x', { resource_id: null, connection_id: null })
    expect([...crossings([step(1, 'CAN_ASSUME', role, elsewhere)], accounts)]).toEqual([[1, 'account 999999999999']])
  })

  it('a card click moves to the first step that ends there, else the one leaving it', () => {
    expect(stepAtCard(steps, 'arn:web')).toBe(2)
    expect(stepAtCard(steps, 'internet')).toBe(1)
    expect(stepAtCard(steps, 'arn:admin')).toBe(5)
    expect(stepAtCard(steps, 'arn:gone')).toBe(1)
  })

  it('Leave route focuses the current step’s resource, else its source, else the entry', () => {
    expect(leaveFocus(steps[4]!, lb)).toBe('arn:admin')
    expect(leaveFocus(step(9, 'X', role, node('arn:removed', { deleted_on: '2026-11-01' })), lb)).toBe('arn:role')
    expect(leaveFocus(step(9, 'X', node('internet'), node('any:s3')), lb)).toBe('arn:lb')
    expect(leaveFocus(null, node('internet'))).toBeNull()
  })

  it('announces a step, its crossing and its level', () => {
    const name = (n: StepOut['source']) => n.name ?? n.uid
    expect(stepAnnouncement(steps[4]!, 5, name, 'demo-shared-services-and-tooling')).toBe(
      'Step 5 of 5. arn:role to arn:admin: can assume. Into demo-shared-services-and-tooling. Configured: The configuration allows it. IAM conditions, SCPs and boundaries are not evaluated.',
    )
    expect(stepAnnouncement(steps[2]!, 5, name, null)).toMatch(/^Step 3 of 5\. .*arn:web.*\. Assumed: /)
  })
})

describe('the layout', () => {
  const ids = ['a', 'b', 'c', 'd', 'e']

  it('is one row when the canvas is wide enough', () => {
    const l = routeLayout(ids, 2400, 700)
    expect([...l.positions.values()].map((p) => [p.x, p.y])).toEqual(ids.map((_, i) => [i * ROUTE_COLUMN, 0]))
    expect(l.lanes).toEqual([])
  })

  it('wraps into the rows that draw the route largest, every row left to right', () => {
    // A canvas beside the docked step list (about 750 x 600): two cards a row.
    expect(perRow(5, 750, 600)).toBe(2)
    const l = routeLayout(ids, 750, 600)
    expect([...l.positions.values()].map((p) => [p.x / ROUTE_COLUMN, p.y / ROUTE_ROW])).toEqual([[0, 0], [1, 0], [0, 1], [1, 1], [0, 2]])
  })

  it('is one column on a tall, narrow canvas', () => {
    expect(perRow(3, 360, 1200)).toBe(1)
    expect([...routeLayout(['a', 'b', 'c'], 360, 1200).positions.values()].map((p) => p.x)).toEqual([0, 0, 0])
  })

  it('a line between rows runs through the gap between them', () => {
    const b = routeBend({ x: ROUTE_COLUMN, y: 0 }, { x: 0, y: ROUTE_ROW })
    expect(b.mid).toEqual({ x: ROUTE_COLUMN / 2, y: ROUTE_ROW / 2 })
    expect(b.weights).toHaveLength(2)
    expect(routeBend({ x: 0, y: 0 }, { x: ROUTE_COLUMN, y: 0 })).toEqual({ weights: [0.5], distances: [0], mid: { x: ROUTE_COLUMN / 2, y: 0 } })
  })
})
