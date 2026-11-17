import { describe, expect, it } from 'vitest'
import { LANE_GAP, NODE_HEIGHT, NODE_WIDTH, ROW, ROUTE_CLEAR, SUB_CLEAR, cardGlyph, hopColumns, hopLabel, laneRows, layout, lineRoute, moveSelection, typeLabel, wrappedPitch, type LaidNode, type Link } from './mapLanes'

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

  it('staggers sub-columns, so a line from one never runs behind a card of another', () => {
    // A zone's six records (2026-11-17): five and one, and a column of 24 in three or more.
    for (const [count, aspect] of [
      [6, 16 / 9],
      [24, 3],
      [24, 6],
    ] as const) {
      const nodes = [n('focus', 'aws_route53_zone'), ...Array.from({ length: count }, (_, i) => n(`r-${String(i).padStart(2, '0')}`, 'aws_route53_record'))]
      const l = layout(nodes, nodes.slice(1).map((r) => ({ source: r.id, target: 'focus' })), 'focus', aspect)
      const cards = [...l.positions.entries()].filter(([id]) => id !== 'focus').map(([, p]) => p)
      const subs = new Set(cards.map((p) => p.x)).size
      expect(subs).toBeGreaterThan(1)
      // A card's line leaves at its own row: every card of another sub-column keeps its middle at
      // least SUB_CLEAR away from that row.
      for (const a of cards) for (const b of cards) if (a.x !== b.x) expect(Math.abs(a.y - b.y)).toBeGreaterThanOrEqual(SUB_CLEAR - 1e-6)
      // And the lines from the cards inside the band run flat to its edge, bending in the gap.
      const focus = l.positions.get('focus')!
      const band = l.lanes.find((b) => b.lane === cards[0]!.lane)!
      const rows = laneRows(l.positions)
      for (const c of cards) {
        const route = lineRoute(c, focus, l.lanes, rows)
        if (c.x + NODE_WIDTH / 2 === band.x + band.width) expect(route).toBeNull()
        else {
          expect(route!.points[0]).toEqual({ x: band.x + band.width, y: c.y })
          expect(route!.points.at(-1)).toEqual({ x: focus.x - NODE_WIDTH / 2, y: focus.y })
        }
      }
    }
  })

  it('keeps an unwrapped column on whole rows, with the plain S between columns', () => {
    const nodes = [n('focus', 'aws_route53_zone'), n('a', 'aws_route53_record'), n('b', 'aws_route53_record'), n('c', 'aws_route53_record')]
    const l = layout(nodes, nodes.slice(1).map((r) => ({ source: r.id, target: 'focus' })), 'focus', 0.5)
    expect([...l.positions.values()].map((p) => p.y).sort((x, y) => x - y)).toEqual([-ROW, 0, 0, ROW])
    const focus = l.positions.get('focus')!
    for (const id of ['a', 'b', 'c']) expect(lineRoute(l.positions.get(id)!, focus, l.lanes, laneRows(l.positions))).toBeNull()
    expect(wrappedPitch(1)).toBe(ROW)
    expect(wrappedPitch(2)).toBe(ROW)
    expect(wrappedPitch(4)).toBe(4 * SUB_CLEAR)
  })

  it('takes a line that skips a column through a gap between its cards, never behind one', () => {
    // p leads to the chosen resource and to q beyond it, and to four more cards in its column:
    // the straight line p -> q would run behind the chosen resource.
    const nodes = ['f', 'p', 'q', 'r1', 'r2', 'r3', 'r4'].map((id) => n(id, 'aws_ec2_instance'))
    const edges: Link[] = [
      { source: 'p', target: 'f' },
      { source: 'f', target: 'q' },
      { source: 'p', target: 'q' },
      ...['r1', 'r2', 'r3', 'r4'].map((r) => ({ source: 'p', target: r })),
    ]
    const l = layout(nodes, edges, 'f', 0.3)
    const at = (id: string) => l.positions.get(id)!
    expect([at('p').lane, at('f').lane, at('q').lane]).toEqual(['hop--1', 'hop-0', 'hop-1'])
    const rows = laneRows(l.positions)
    const route = lineRoute(at('p'), at('q'), l.lanes, rows)!
    const middle = l.lanes.find((b) => b.lane === 'hop-0')!
    const inside = route.points.filter((pt) => pt.x >= middle.x && pt.x <= middle.x + middle.width)
    expect(inside.length).toBeGreaterThanOrEqual(2)
    const crossing = inside[0]!.y
    expect(inside.every((pt) => pt.y === crossing)).toBe(true) // flat inside the column
    for (const y of rows.get('hop-0')!) expect(Math.abs(y - crossing)).toBeGreaterThanOrEqual(ROUTE_CLEAR)
    // It bends only in the gaps: every change of height is outside every band.
    route.points.forEach((pt, i) => {
      const prev = route.points[i - 1]
      if (prev && prev.y !== pt.y) expect(l.lanes.some((b) => pt.x > b.x && pt.x < b.x + b.width)).toBe(false)
    })
    // Neighbouring columns with their cards at the edges keep the plain S.
    expect(lineRoute(at('p'), at('f'), l.lanes, rows)).toBeNull()
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
