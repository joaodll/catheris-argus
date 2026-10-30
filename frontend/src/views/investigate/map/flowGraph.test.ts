import { describe, expect, it } from 'vitest'
import { chipSummary, columnLabel, flowView, type FlowDetail } from './flowGraph'
import { flowLayout } from './mapLanes'

const node = (uid: string, type: string | null = 'aws_lambda_function', kind: 'resource' | 'internet' = 'resource') => ({
  uid,
  kind,
  resource_id: kind === 'resource' ? 1 : null,
  type: kind === 'resource' ? type : null,
  name: uid,
  region: 'us-east-1',
  connection_id: 1,
  deleted_on: null,
  expanded: false,
  boundary: false,
  findings: {},
})
const edge = (id: number, source: string, target: string, type = 'ROUTES_TO') => ({
  id,
  source_uid: source,
  target_uid: target,
  type,
  origin: 'rule:x@1',
  attributes: {},
  first_seen: '2026-10-09',
  last_seen: '2026-10-09',
})
const step = (col: number, kind: 'edge' | 'dns' | 'uses' | 'group', source: string, target: string | null, ids: number[], extra = {}) => ({
  col,
  kind,
  source_uid: source,
  target_uid: target,
  via_uid: null,
  edge_ids: ids,
  group_type: null,
  group_count: null,
  ...extra,
})

const detail: FlowDetail = {
  id: 7,
  connection_id: 1,
  entry_uid: 'cdn',
  reach: 'open',
  truncated: false,
  as_of: '2026-10-09',
  data_through: '2026-10-09',
  nodes: [node('internet', null, 'internet'), node('rec', 'aws_route53_record'), node('cdn', 'aws_cloudfront_distribution'), node('fn'), node('table', 'aws_dynamodb_table')],
  steps: [
    step(1, 'dns', 'internet', 'rec', []),
    step(2, 'edge', 'rec', 'cdn', [1]),
    step(3, 'edge', 'cdn', 'fn', [2]),
    step(4, 'uses', 'fn', 'table', [3, 4], { via_uid: 'role' }),
    step(4, 'group', 'fn', null, [5], { group_type: 'aws_sqs_queue', group_count: 30 }),
  ],
  chips: [
    { node_uid: 'fn', kind: 'role', chip_uid: 'role', name: 'orders-role', edge_id: 3 },
    { node_uid: 'fn', kind: 'security_group', chip_uid: 'sg-1', name: 'app', edge_id: 8 },
    { node_uid: 'fn', kind: 'security_group', chip_uid: 'sg-2', name: 'db', edge_id: 9 },
  ],
  edges: [edge(1, 'rec', 'cdn'), edge(2, 'cdn', 'fn'), edge(3, 'fn', 'role', 'RUNS_AS'), edge(4, 'role', 'table', 'ACCESSES'), edge(5, 'fn', 'q1', 'TRIGGERS')],
}

describe('Flow mode', () => {
  it('turns a flow into the map graph, columns and chips', () => {
    const view = flowView(detail)
    expect(Object.fromEntries(view.columns)).toMatchObject({ internet: 0, rec: 1, cdn: 2, fn: 3, table: 4 })
    expect(view.entryCol).toBe(2)
    const lines = [...view.graph.edges.values()].map((e) => [e.source_uid, e.target_uid, e.type])
    expect(lines).toEqual(
      expect.arrayContaining([
        ['internet', 'rec', 'RESOLVES'],
        ['rec', 'cdn', 'ROUTES_TO'],
        ['fn', 'table', 'USES'],
      ]),
    )
    // The role is a chip, not a node, and the RUNS_AS/ACCESSES edges are not drawn on their own.
    expect(view.graph.nodes.has('role')).toBe(false)
    expect([...view.graph.edges.keys()].filter((id) => id > 0).sort()).toEqual([1, 2])
    const [group] = [...view.graph.groups.values()]
    expect(group).toMatchObject({ anchor_uid: 'fn', edge_type: 'TRIGGERS', resource_type: 'aws_sqs_queue', count: 30 })
    expect(view.columns.get(`group:${group!.id}`)).toBe(4)
    expect(chipSummary(view.chips.get('fn')!)).toEqual([
      { kind: 'role', text: 'Role', title: 'Role: orders-role' },
      { kind: 'security_group', text: 'SG 2', title: 'Security groups: app, db' },
    ])
  })

  it('names the columns from the entry', () => {
    expect([0, 1, 2, 3, 5].map((c) => columnLabel(c, 2))).toEqual(['Internet', 'DNS', 'Entry', 'Step 1', 'Step 3'])
  })

  it('lays out one column per step, hiding empty ones', () => {
    const laid = flowLayout(
      [
        { id: 'a', kind: 'internet', type: null, name: 'a', rank: 5 },
        { id: 'b', kind: 'resource', type: null, name: 'b', rank: 5 },
        { id: 'c', kind: 'resource', type: null, name: 'c', rank: 5 },
      ],
      new Map([['a', 0], ['b', 2], ['c', 2]]),
      (col) => `C${col}`,
    )
    expect(laid.lanes.map((l) => [l.lane, l.label, l.x])).toEqual([['col-0', 'C0', 0], ['col-2', 'C2', 206]])
    expect(laid.positions.get('b')!.y).toBe(-35)
  })
})
