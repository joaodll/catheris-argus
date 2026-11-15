import { describe, expect, it } from 'vitest'
import { GROUP_HEADER, LANE_GAP, LANE_WIDTH, NODE_HEIGHT, ROW, cardGlyph, hopColumns, hopLabel, layout, moveSelection, typeLabel, type LaidNode } from './mapLanes'

const n = (id: string, type: string | null, extra: Partial<LaidNode> = {}): LaidNode => ({ id, kind: 'resource', type, name: id, ...extra })

describe('Resource map columns', () => {
  it('labels types briefly', () => {
    expect(typeLabel('aws_lambda_function')).toBe('Lambda')
    expect(typeLabel('aws_ec2_target_group')).toBe('Target group')
    expect(typeLabel('aws_glue_job')).toBe('glue job')
  })

  it('counts hops from the focus: sources left, targets right, the nearest hop wins', () => {
    const edges = [
      { source: 'internet', target: 'www' },
      { source: 'www', target: 'app' },
      { source: 'app', target: 'alb' },
      { source: 'alb', target: 'tg' },
      { source: 'tg', target: 'i-1' },
      { source: 'internet', target: 'alb' },
    ]
    const cols = hopColumns(['internet', 'www', 'app', 'alb', 'tg', 'i-1'], edges, 'alb')
    expect(Object.fromEntries(cols)).toEqual({ alb: 0, tg: 1, 'i-1': 2, app: -1, internet: -1, www: -2 })
  })

  it('starts from what nothing points to without a focus, and is order-independent', () => {
    const edges = [
      { source: 'r1', target: 'r2' },
      { source: 'r2', target: 'lb' },
    ]
    const cols = hopColumns(['lb', 'r2', 'r1', 'lone'], edges, null)
    expect(Object.fromEntries(cols)).toEqual({ r1: 0, r2: 1, lb: 2, lone: 0 })
    expect(hopColumns(['r1', 'lone', 'lb', 'r2'], [...edges].reverse(), null)).toEqual(cols)
  })

  it('names the columns', () => {
    expect([-2, -1, 0, 1, 3].map((c) => hopLabel(c, true))).toEqual(['2 hops in', '1 hop in', 'Selected', '1 hop out', '3 hops out'])
    expect(hopLabel(0, false)).toBe('Step 1')
  })

  it('places columns left to right, hides empty ones, and centres the focus', () => {
    const nodes = [n('internet', null, { kind: 'internet' }), n('fn-b', 'aws_lambda_function'), n('fn-a', 'aws_lambda_function'), n('focus', 'aws_lambda_function'), n('role', 'aws_iam_role')]
    const edges = [
      { source: 'internet', target: 'focus' },
      { source: 'focus', target: 'fn-a' },
      { source: 'focus', target: 'fn-b' },
      { source: 'focus', target: 'role' },
    ]
    const { positions, lanes } = layout(nodes, edges, 'focus')
    expect(lanes.map((l) => [l.lane, l.label])).toEqual([
      ['hop--1', '1 hop in'],
      ['hop-0', 'Selected'],
      ['hop-1', '1 hop out'],
    ])
    const step = LANE_WIDTH + LANE_GAP
    expect(lanes.map((l) => l.x)).toEqual([0, step, 2 * step])
    expect(positions.get('focus')).toEqual({ x: step + LANE_WIDTH / 2, y: 0, lane: 'hop-0' })
    // One kind (no layer given: Other), under one header, by name, ROW apart, centred on 0.
    const ys = ['fn-a', 'fn-b', 'role'].map((id) => positions.get(id)!.y)
    expect(ys[1]! - ys[0]!).toBe(ROW)
    expect(ys[2]! - ys[1]!).toBe(ROW)
    expect(ys[0]! - ROW / 2 - GROUP_HEADER + ys[2]! + ROW / 2).toBe(0)
  })

  it('groups a column by kind, in a fixed order, each under its header', () => {
    const nodes = [n('focus', 'aws_ec2_instance'), n('sg', 'aws_vpc_security_group'), n('subnet', 'aws_vpc_subnet'), n('role', 'aws_iam_role'), n('alb', 'aws_ec2_application_load_balancer'), n('internet', null, { kind: 'internet' })]
    const edges = [
      { source: 'focus', target: 'sg', layer: 'network' },
      { source: 'focus', target: 'subnet', layer: 'network' },
      { source: 'focus', target: 'role', layer: 'identity' },
      { source: 'alb', target: 'focus', layer: 'traffic' },
      { source: 'internet', target: 'focus', layer: 'traffic' },
    ]
    const { positions, headers } = layout(nodes, edges, 'focus')
    const y = (id: string) => positions.get(id)!.y
    // Out: Network (sg, subnet) above Identity (role); in: Traffic (alb) above Other (internet).
    expect(y('sg')).toBeLessThan(y('subnet'))
    expect(y('subnet')).toBeLessThan(y('role'))
    expect(y('alb')).toBeLessThan(y('internet'))
    expect(headers.map((h) => h.label).sort()).toEqual(['Identity', 'Network', 'Other', 'Traffic'])
    // A header sits above its group's first card; the focus stays at 0 with no header.
    const network = headers.find((h) => h.label === 'Network')!
    expect(network.y).toBeLessThan(y('sg') - NODE_HEIGHT / 2)
    expect(y('focus')).toBe(0)
  })

  it('puts a card beside what it connects to (barycentre), so lines cross less', () => {
    // Two first-hop roles; their policies two hops out sit in the same order as the roles,
    // whatever their names say.
    const nodes = [n('focus', 'aws_lambda_function'), n('role-a', 'aws_iam_role'), n('role-b', 'aws_iam_role'), n('z-policy', 'aws_iam_policy'), n('a-policy', 'aws_iam_policy')]
    const edges = [
      { source: 'focus', target: 'role-a', layer: 'identity' },
      { source: 'focus', target: 'role-b', layer: 'identity' },
      { source: 'role-a', target: 'z-policy', layer: 'policy' },
      { source: 'role-b', target: 'a-policy', layer: 'policy' },
    ]
    const { positions } = layout(nodes, edges, 'focus')
    expect(positions.get('role-a')!.y).toBeLessThan(positions.get('role-b')!.y)
    expect(positions.get('z-policy')!.y).toBeLessThan(positions.get('a-policy')!.y)
  })

  it('leaves the space the owner asked for (ADR-0051)', () => {
    // A line's word between two columns ("is administrator" is about 90 px), with room to spare.
    expect(LANE_GAP).toBeGreaterThanOrEqual(90 + 2 * 32)
    // More between two cards than the first map's 24 px.
    expect(ROW - NODE_HEIGHT).toBeGreaterThanOrEqual(40)
  })

  it("draws a card's glyph from its kind, then its type", () => {
    expect(cardGlyph('internet', null)).toBe('globe')
    expect(cardGlyph('external', null)).toBe('external')
    expect(cardGlyph('any', null)).toBe('external')
    expect(cardGlyph('resource', 'aws_lambda_function')).toBe('lambda')
    expect(cardGlyph('group', 'aws_s3_bucket')).toBe('bucket')
    expect(cardGlyph('resource', null)).toBe('cube')
  })

  it('is the same every time for the same view', () => {
    const nodes = [n('b', 'aws_s3_bucket'), n('a', 'aws_s3_bucket'), n('c', 'aws_iam_role')]
    const edges = [{ source: 'c', target: 'a' }]
    expect(layout(nodes, edges, null)).toEqual(layout([...nodes].reverse(), edges, null))
  })

  it('moves the selection with the arrow keys', () => {
    const nodes = [n('internet', null, { kind: 'internet' }), n('f1', 'aws_lambda_function'), n('f2', 'aws_lambda_function'), n('role', 'aws_iam_role')]
    const edges = [
      { source: 'internet', target: 'f1' },
      { source: 'internet', target: 'f2' },
      { source: 'f1', target: 'role' },
    ]
    const { positions } = layout(nodes, edges, 'internet')
    expect(moveSelection(positions, null, 'down', 'f1')).toBe('f1')
    expect(moveSelection(positions, 'f1', 'down', 'f1')).toBe('f2')
    expect(moveSelection(positions, 'f2', 'down', 'f1')).toBe('f2')
    expect(moveSelection(positions, 'f1', 'left', 'f1')).toBe('internet')
    expect(moveSelection(positions, 'f1', 'right', 'f1')).toBe('role')
    expect(moveSelection(positions, 'role', 'right', 'f1')).toBe('role')
  })
})
