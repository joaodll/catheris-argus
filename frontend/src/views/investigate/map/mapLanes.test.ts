import { describe, expect, it } from 'vitest'
import { LANE_GAP, NODE_HEIGHT, NODE_WIDTH, ROW, cardGlyph, hopColumns, hopLabel, layout, moveSelection, typeLabel, type LaidNode, type Link } from './mapLanes'

const n = (id: string, type: string | null, extra: Partial<LaidNode> = {}): LaidNode => ({ id, kind: 'resource', type, name: id, ...extra })

describe('the map columns', () => {
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

  it("draws a card's glyph from its kind, then its type", () => {
    expect(cardGlyph('internet', null)).toBe('globe')
    expect(cardGlyph('external', null)).toBe('external')
    expect(cardGlyph('any', null)).toBe('external')
    expect(cardGlyph('resource', 'aws_lambda_function')).toBe('lambda')
    expect(cardGlyph('group', 'aws_s3_bucket')).toBe('bucket')
    expect(cardGlyph('resource', null)).toBe('cube')
  })

  it('places columns left to right, hides empty ones, and keeps the focus at 0', () => {
    const nodes = [n('internet', null, { kind: 'internet' }), n('fn-b', 'aws_lambda_function'), n('fn-a', 'aws_lambda_function'), n('focus', 'aws_lambda_function'), n('role', 'aws_iam_role')]
    const edges = [
      { source: 'internet', target: 'focus' },
      { source: 'focus', target: 'fn-a' },
      { source: 'focus', target: 'fn-b' },
      { source: 'focus', target: 'role' },
    ]
    const { positions, lanes } = layout(nodes, edges, 'focus', 1)
    expect(lanes.map((l) => [l.lane, l.label])).toEqual([
      ['hop--1', '1 hop in'],
      ['hop-0', 'Selected'],
      ['hop-1', '1 hop out'],
    ])
    const step = NODE_WIDTH + LANE_GAP
    // The chosen resource's column is at x = 0; the others are laid outwards from it.
    expect(lanes.map((l) => l.x)).toEqual([-step, 0, step])
    expect(positions.get('focus')).toEqual({ x: NODE_WIDTH / 2, y: 0, lane: 'hop-0' })
    // No grouping by type: by name, ROW apart, centred on 0.
    const ys = ['fn-a', 'fn-b', 'role'].map((id) => positions.get(id)!.y)
    expect(ys).toEqual([-ROW, 0, ROW])
  })

  it('treats a subnet and a VPC as ordinary cards with their lines', () => {
    const nodes = [n('i', 'aws_ec2_instance'), n('sn', 'aws_vpc_subnet'), n('vpc', 'aws_vpc')]
    const edges: Link[] = [
      { source: 'i', target: 'sn', type: 'IN_NETWORK' },
      { source: 'sn', target: 'vpc', type: 'IN_NETWORK' },
    ]
    const { positions } = layout(nodes, edges, 'i')
    expect(positions.get('sn')!.lane).toBe('hop-1')
    expect(positions.get('vpc')!.lane).toBe('hop-2')
  })

  it('puts a card beside what it connects to (barycentre), so lines cross less', () => {
    const nodes = [n('focus', 'aws_lambda_function'), n('role-a', 'aws_iam_role'), n('role-b', 'aws_iam_role'), n('z-policy', 'aws_iam_policy'), n('a-policy', 'aws_iam_policy')]
    const edges = [
      { source: 'focus', target: 'role-a' },
      { source: 'focus', target: 'role-b' },
      { source: 'role-a', target: 'z-policy' },
      { source: 'role-b', target: 'a-policy' },
    ]
    const { positions } = layout(nodes, edges, 'focus', 1)
    expect(positions.get('role-a')!.y).toBeLessThan(positions.get('role-b')!.y)
    expect(positions.get('z-policy')!.y).toBeLessThan(positions.get('a-policy')!.y)
  })

  it('never moves a card for a security line, and puts a card only a security line reaches beside it', () => {
    const nodes = [n('fn', 'aws_lambda_function'), n('role-a', 'aws_iam_role'), n('role-b', 'aws_iam_role'), n('bucket', 'aws_s3_bucket')]
    const plain: Link[] = [
      { source: 'fn', target: 'role-b' },
      { source: 'fn', target: 'role-a' },
      { source: 'role-a', target: 'bucket' },
    ]
    // The Security view: a shortcut line, and an administrator only IS_ADMIN reaches.
    const security: Link[] = [...plain, { source: 'fn', target: 'bucket', type: 'CAN_ESCALATE_TO' }, { source: 'role-b', target: 'admin:1', type: 'IS_ADMIN' }]
    const before = layout(nodes, plain, 'fn', 1).positions
    const after = layout([...nodes, n('admin:1', null, { kind: 'admin' })], security, 'fn', 1).positions
    for (const [id, p] of before) expect(after.get(id)).toEqual(p)
    expect(after.get('admin:1')!.lane).toBe('hop-2')
  })

  it('wraps a tall column into sub-columns on a wide canvas, without overlapping cards', () => {
    const nodes = [n('focus', 'aws_iam_role'), ...Array.from({ length: 24 }, (_, i) => n(`fn-${String(i).padStart(2, '0')}`, 'aws_lambda_function'))]
    const edges = nodes.slice(1).map((f) => ({ source: f.id, target: 'focus' }))
    const wide = layout(nodes, edges, 'focus', 3)
    const tall = layout(nodes, edges, 'focus', 0.3)
    const columns = (l: ReturnType<typeof layout>) => new Set([...l.positions.values()].map((p) => p.x)).size
    expect(columns(wide)).toBeGreaterThan(columns(tall))
    for (const l of [wide, tall]) {
      const all = [...l.positions.values()]
      for (let i = 0; i < all.length; i++)
        for (let j = i + 1; j < all.length; j++) {
          const a = all[i]!
          const b = all[j]!
          expect(Math.abs(a.x - b.x) >= NODE_WIDTH || Math.abs(a.y - b.y) >= NODE_HEIGHT).toBe(true)
        }
    }
  })

  it('leaves the space the owner asked for', () => {
    expect(LANE_GAP).toBeGreaterThanOrEqual(90 + 2 * 32)
    expect(ROW - NODE_HEIGHT).toBeGreaterThanOrEqual(40)
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
    const { positions } = layout(nodes, edges, 'internet', 1)
    expect(moveSelection(positions, null, 'down', 'f1')).toBe('f1')
    expect(moveSelection(positions, 'f1', 'down', 'f1')).toBe('f2')
    expect(moveSelection(positions, 'f2', 'down', 'f1')).toBe('f2')
    expect(moveSelection(positions, 'f1', 'left', 'f1')).toBe('internet')
    expect(moveSelection(positions, 'f1', 'right', 'f1')).toBe('role')
    expect(moveSelection(positions, 'role', 'right', 'f1')).toBe('role')
  })

  it('lays out 500 cards with a hub quickly enough to redraw on Expand', () => {
    const nodes: LaidNode[] = [n('hub', 'aws_iam_role')]
    const edges: Link[] = []
    const types = ['aws_ec2_instance', 'aws_lambda_function', 'aws_iam_role', 'aws_s3_bucket', 'aws_vpc_security_group']
    for (let i = 0; nodes.length < 500; i++) {
      const id = `r-${String(i).padStart(3, '0')}`
      nodes.push(n(id, types[i % types.length]!))
      edges.push(i % 3 ? { source: id, target: 'hub' } : { source: `r-${String(Math.floor(i / 3)).padStart(3, '0')}`, target: id })
    }
    const started = performance.now()
    const result = layout(nodes, edges, 'hub')
    expect(result.positions.size).toBe(500)
    expect(performance.now() - started).toBeLessThan(1500)
  })
})
