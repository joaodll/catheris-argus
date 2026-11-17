/**
 * The map's columns (ADR-0051, as amended 2026-11-15 by the owner, palace decisions/97db351b): the
 * chain in the order traffic and access follow it, one column per hop counted from the chosen
 * resource, what leads to it on the left and what it leads to on the right. There is no grouping
 * by type: a card sits beside what it connects to. Subnets and VPCs are ordinary cards. Positions
 * are computed here and handed to Cytoscape's preset layout: the same view always places a node in
 * the same spot, and a security line never moves a card, so the view switch moves nothing.
 */
import type { IconName } from '@/components/icons'
import { resourceGlyph } from '../resourceGlyph'
import { SECURITY_EDGE_TYPES } from './mapFacts'

export const NODE_WIDTH = 208
export const NODE_HEIGHT = 64
// Room for a line's word at its midpoint, clear of the cards on both sides. The longest word,
// "is administrator", is about 90 px.
export const LANE_GAP = 168
// From one card's middle to the next in a column: 40 px between cards.
export const ROW = NODE_HEIGHT + 40
// A tall column wraps into sub-columns this far apart.
export const SUB_GAP = 48
// In a wrapped column each sub-column sits lower than the one before by its share of a row, so
// a line from an outer sub-column runs between the cards of the inner ones (2026-11-17: a line
// ran behind a card on its row). The share keeps at least this much between a card's middle and
// such a line; with three or more sub-columns the column's rows spread to keep it.
export const SUB_CLEAR = NODE_HEIGHT / 2 + 8

/** The row pitch of a column wrapped into `subs` sub-columns: ROW, or more when the staggered
 * sub-columns would leave a line closer than SUB_CLEAR to a card's middle. */
export function wrappedPitch(subs: number): number {
  return subs > 1 ? Math.max(ROW, subs * SUB_CLEAR) : ROW
}
// How far above the highest card a column's name sits.
export const LANE_NAME_RISE = 64

/** The kinds the panel's Connections tab groups lines by (owner, 2026-11-14, decisions/52e3c4c5):
 * the API's layers, then Other (pseudo-nodes, external hosts, a line of no layer). */
export const KINDS = ['traffic', 'network', 'identity', 'policy', 'data', 'other'] as const
export type Kind = (typeof KINDS)[number]
export const KIND_LABEL: Record<Kind, string> = { traffic: 'Traffic', network: 'Network', identity: 'Identity', policy: 'IAM policy', data: 'Data access', other: 'Other' }

export type NodeKind = 'resource' | 'internet' | 'admin' | 'external' | 'any' | 'group'

/** The short type label on a node's second line: "Lambda", "Target group", "API Gateway". */
const TYPE_LABELS: [RegExp, string][] = [
  [/^aws_lambda_function$/, 'Lambda'],
  [/^aws_ec2_instance$/, 'EC2 instance'],
  [/^aws_ec2_target_group$/, 'Target group'],
  [/^aws_ec2_application_load_balancer$/, 'ALB'],
  [/^aws_ec2_network_load_balancer$/, 'NLB'],
  [/^aws_ec2_.*load_balancer/, 'Load balancer'],
  [/^aws_api_gateway/, 'API Gateway'],
  [/^aws_cloudfront_distribution$/, 'CloudFront'],
  [/^aws_route53_record$/, 'Route53 record'],
  [/^aws_route53_zone$/, 'Route53 zone'],
  [/^aws_ecs_service$/, 'ECS service'],
  [/^aws_ecs_cluster$/, 'ECS cluster'],
  [/^aws_eks_cluster$/, 'EKS cluster'],
  [/^aws_s3_bucket$/, 'S3 bucket'],
  [/^aws_rds_db_instance$/, 'RDS instance'],
  [/^aws_dynamodb_table$/, 'DynamoDB table'],
  [/^aws_sqs_queue$/, 'SQS queue'],
  [/^aws_sns_topic$/, 'SNS topic'],
  [/^aws_iam_role$/, 'IAM role'],
  [/^aws_iam_user$/, 'IAM user'],
  [/^aws_iam_policy$/, 'IAM policy'],
  [/^aws_iam_group$/, 'IAM group'],
  [/^aws_vpc_security_group$/, 'Security group'],
  [/^aws_vpc_subnet$/, 'Subnet'],
  [/^aws_vpc$/, 'VPC'],
  [/^aws_kms_key$/, 'KMS key'],
  [/^aws_sfn_state_machine$/, 'State machine'],
  [/^aws_pipes_pipe$/, 'EventBridge pipe'],
  [/^aws_scheduler_schedule$/, 'Schedule'],
  [/^aws_eventbridge_rule$/, 'EventBridge rule'],
  [/^aws_kinesis_firehose_delivery_stream$/, 'Firehose'],
  [/^aws_kinesis_stream$/, 'Kinesis stream'],
  [/^aws_cloudwatch_log_group$/, 'Log group'],
  [/^aws_wafv2_web_acl$/, 'WAF web ACL'],
  [/^aws_secretsmanager_secret$/, 'Secret'],
]

/** A card's glyph: the resource type's (a group's members' type), the internet's globe, or the
 * mark of something outside the inventory. */
export function cardGlyph(kind: NodeKind | string, type: string | null): IconName {
  if (kind === 'internet') return 'globe'
  if (kind === 'external' || kind === 'any') return 'external'
  return resourceGlyph(type)
}

export function typeLabel(type: string | null): string {
  if (!type) return 'Not in the inventory'
  for (const [pattern, label] of TYPE_LABELS) if (pattern.test(type)) return label
  return type.replace(/^aws_/, '').replace(/_/g, ' ')
}

// ---- Layout.

export interface LaidNode {
  id: string
  kind: NodeKind
  type: string | null
  name: string
}

export interface Placed {
  x: number
  y: number
  // A hop column ("hop-<n>").
  lane: string
}

export interface Layout {
  positions: Map<string, Placed>
  // The hop columns that hold a card, left to right: the name, and the left edge and width of
  // the column's band (a tall column wraps into several sub-columns side by side).
  lanes: { lane: string; label: string; x: number; width: number }[]
}

export interface Link {
  source: string
  target: string
  // The line's layer (the API's); a group of no layer goes under Other.
  layer?: string | null
  // The edge type: a security line never moves a card.
  type?: string | null
}

/**
 * Each node's column: hops from the focus, negative for what leads to it and positive for what
 * it leads to, breadth first so a node takes its nearest hop. Without a focus, or for a part of
 * the view the focus does not reach, the nodes nothing points to start at 0. Ids are visited in
 * sorted order, so the result does not depend on the order the API returned them.
 */
export function hopColumns(ids: string[], edges: Link[], focus: string | null): Map<string, number> {
  const known = new Set(ids)
  const out = new Map<string, string[]>()
  const into = new Map<string, string[]>()
  for (const e of edges) {
    if (!known.has(e.source) || !known.has(e.target) || e.source === e.target) continue
    out.set(e.source, [...(out.get(e.source) ?? []), e.target])
    into.set(e.target, [...(into.get(e.target) ?? []), e.source])
  }
  const cols = new Map<string, number>()
  const walk = (starts: string[]) => {
    let frontier = starts.filter((id) => !cols.has(id))
    for (const id of frontier) cols.set(id, 0)
    while (frontier.length) {
      const next: string[] = []
      for (const id of [...frontier].sort()) {
        const col = cols.get(id)!
        const steps: [string[], number][] = [
          [out.get(id) ?? [], col + 1],
          [into.get(id) ?? [], col - 1],
        ]
        for (const [ids, at] of steps) {
          for (const other of [...ids].sort()) {
            if (cols.has(other)) continue
            cols.set(other, at)
            next.push(other)
          }
        }
      }
      frontier = next
    }
  }
  const sorted = [...known].sort()
  if (focus != null && known.has(focus)) walk([focus])
  walk(sorted.filter((id) => !cols.has(id) && !(into.get(id) ?? []).length))
  for (const id of sorted) if (!cols.has(id)) walk([id]) // a cycle with no start
  return cols
}

/** A column's header: "2 hops in", "Selected", "1 hop out"; without a focus, "Step n". */
export function hopLabel(col: number, focused: boolean): string {
  if (!focused) return `Step ${col + 1}`
  if (col === 0) return 'Selected'
  const n = Math.abs(col)
  return `${n} ${n === 1 ? 'hop' : 'hops'} ${col < 0 ? 'in' : 'out'}`
}


const isSecurity = (e: Link) => !!e.type && SECURITY_EDGE_TYPES.has(e.type)

/**
 * The columns from the lines both views draw, and the cards only a security line reaches (the
 * internet on CloudFox's reach, an administrator): `late`. A late card takes the column beside the
 * card it is linked to and goes below that column's other cards, so the Security view never moves
 * a card the Infrastructure view also draws.
 */
function columnsOf(ids: string[], edges: Link[], focus: string | null): { cols: Map<string, number>; late: Set<string> } {
  const plain = edges.filter((e) => !isSecurity(e))
  const linked = new Set(plain.flatMap((e) => (e.source === e.target ? [] : [e.source, e.target])))
  if (focus != null) linked.add(focus)
  const cols = hopColumns(ids.filter((id) => linked.has(id)), plain, focus)
  const late = new Set(ids.filter((id) => !cols.has(id)))
  const rest = [...late].sort()
  for (let pass = 0; pass < 4 && rest.some((id) => !cols.has(id)); pass++) {
    for (const id of rest) {
      if (cols.has(id)) continue
      const near = edges
        .filter(isSecurity)
        .flatMap((e) => (e.source === id && cols.has(e.target) ? [cols.get(e.target)! - 1] : e.target === id && cols.has(e.source) ? [cols.get(e.source)! + 1] : []))
      if (near.length) cols.set(id, near.sort((a, b) => Math.abs(a) - Math.abs(b) || a - b)[0]!)
    }
  }
  const left = rest.filter((id) => !cols.has(id))
  for (const [id, col] of hopColumns(left, edges, null)) cols.set(id, col)
  return { cols, late }
}

/**
 * One column per hop (columnsOf), the chosen resource's column at x = 0, what leads to it to the
 * left and what it leads to to the right; empty columns hidden. The focus sits in the middle of its
 * column at y = 0. Every other column is laid out from the focus outwards, its cards ordered by the
 * mean row of what they connect to in the column nearer the focus (barycentre), then by name, so a
 * card sits beside what it connects to and lines cross less. A column taller than `rows` cards
 * wraps into sub-columns side by side; `rows` is chosen so the drawing's shape comes closest to
 * the canvas's (`aspect`, width / height). A card's place never depends on a security fact or a
 * security line: the late cards (columnsOf) are left out of every choice and go last.
 */
export function layout(nodes: LaidNode[], edges: Link[], focus: string | null, aspect = 16 / 9): Layout {
  const sorted = [...nodes].sort((a, b) => a.id.localeCompare(b.id))
  const { cols, late } = columnsOf(
    sorted.map((n) => n.id),
    edges,
    focus,
  )
  const counts = new Map<number, number>()
  for (const [id, c] of cols) if (!late.has(id)) counts.set(c, (counts.get(c) ?? 0) + 1)
  const tallest = Math.max(1, ...counts.values())
  let best: Layout | null = null
  let bestScore = Infinity
  for (const rows of new Set([3, 4, 5, 6, 8, 10, 12, 15, 20, tallest].filter((r) => r <= tallest))) {
    const candidate = layoutWith(sorted, edges, focus, cols, late, rows)
    const box = bounds(candidate, late)
    const score = Math.abs(Math.log(Math.max(box.w, 1) / Math.max(box.h, 1) / aspect))
    if (score < bestScore - 1e-9) {
      best = candidate
      bestScore = score
    }
  }
  return best ?? layoutWith(sorted, edges, focus, cols, late, tallest)
}

function bounds(l: Layout, skip: Set<string>): { w: number; h: number } {
  let x1 = Infinity
  let x2 = -Infinity
  let y1 = Infinity
  let y2 = -Infinity
  for (const [id, p] of l.positions) {
    if (skip.has(id)) continue
    x1 = Math.min(x1, p.x - NODE_WIDTH / 2)
    x2 = Math.max(x2, p.x + NODE_WIDTH / 2)
    y1 = Math.min(y1, p.y - NODE_HEIGHT / 2)
    y2 = Math.max(y2, p.y + NODE_HEIGHT / 2)
  }
  return Number.isFinite(x1) ? { w: x2 - x1, h: y2 - y1 } : { w: 0, h: 0 }
}

function layoutWith(nodes: LaidNode[], edges: Link[], focus: string | null, cols: Map<string, number>, late: Set<string>, rows: number): Layout {
  const focused = focus != null && cols.has(focus)
  const members = new Map<number, LaidNode[]>()
  for (const n of nodes) {
    const col = cols.get(n.id)!
    members.set(col, [...(members.get(col) ?? []), n])
  }
  const shown = [...members.keys()].sort((a, b) => a - b)
  const plain = edges.filter((e) => !isSecurity(e))
  const positions = new Map<string, Placed>()
  const byName = (a: LaidNode, b: LaidNode) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)
  // Each column's cards in order, from the focus outwards: a column reads the rows of the
  // column nearer the focus, already placed. Late cards are not in `order`.
  const ordered = new Map<number, LaidNode[]>()
  const rowOf = new Map<string, number>()
  for (const col of [...shown].sort((a, b) => Math.abs(a) - Math.abs(b) || a - b)) {
    const list = members.get(col)!.filter((n) => !late.has(n.id))
    let order: LaidNode[]
    if (col === 0 || !focused) {
      const rest = list.filter((n) => n.id !== focus).sort(byName)
      const f = list.find((n) => n.id === focus)
      order = f ? [...rest.slice(0, Math.floor(rest.length / 2)), f, ...rest.slice(Math.floor(rest.length / 2))] : rest
    } else {
      const near = col > 0 ? col - 1 : col + 1
      const bary = (n: LaidNode): number => {
        const ys = plain.flatMap((l) => {
          const other = l.source === n.id ? l.target : l.target === n.id ? l.source : null
          return other != null && other !== n.id && cols.get(other) === near && rowOf.has(other) ? [rowOf.get(other)!] : []
        })
        return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : 0
      }
      order = list.map((n) => ({ n, b: bary(n) })).sort((a, b) => a.b - b.b || byName(a.n, b.n)).map((x) => x.n)
    }
    ordered.set(col, order)
    // A row's height is the same in every column: the rows are centred on 0.
    order.forEach((n, i) => rowOf.set(n.id, (i % rows) - (Math.min(rows, order.length) - 1) / 2))
  }
  // Column bands, from the chosen resource's column outwards, so a column only late cards fill
  // (at either end) never shifts the others.
  const widthOf = (col: number) => {
    const subs = Math.max(1, Math.ceil(ordered.get(col)!.length / rows))
    return subs * NODE_WIDTH + (subs - 1) * SUB_GAP
  }
  const anchor = shown.includes(0) ? 0 : shown[0]!
  const left = new Map<number, number>([[anchor, 0]])
  for (let c = anchor + 1, x = widthOf(anchor) + LANE_GAP; shown.includes(c); x += widthOf(c) + LANE_GAP, c++) left.set(c, x)
  for (let c = anchor - 1, x = 0; shown.includes(c); c--) {
    x -= widthOf(c) + LANE_GAP
    left.set(c, x)
  }
  const lanes: Layout['lanes'] = []
  for (const col of shown) {
    const order = ordered.get(col)!
    const lane = `hop-${col}`
    const x = left.get(col) ?? 0
    lanes.push({ lane, label: hopLabel(col, focused), x, width: widthOf(col) })
    // Every sub-column on the first one's rows, the k-th of n lower by k/n of a row, and a
    // shorter last one centred on those rows: no card sits on a line from a sub-column beside it.
    const subs = Math.max(1, Math.ceil(order.length / rows))
    const pitch = wrappedPitch(subs)
    const first = Math.min(rows, order.length)
    order.forEach((n, i) => {
      const sub = Math.floor(i / rows)
      const inSub = Math.min(rows, order.length - sub * rows)
      const row = (i % rows) + Math.floor((first - inSub) / 2) - (first - 1) / 2
      positions.set(n.id, { x: x + sub * (NODE_WIDTH + SUB_GAP) + NODE_WIDTH / 2, y: (row + sub / subs) * pitch, lane })
    })
  }
  // The focus stays at y = 0 (its column is centred on it).
  if (focus && positions.has(focus)) {
    const f = positions.get(focus)!
    if (f.y !== 0) for (const [id, p] of positions) if (p.lane === f.lane) positions.set(id, { ...p, y: p.y - f.y })
  }
  // Late cards: below the last card of their column's last sub-column, by name.
  for (const col of shown) {
    const lates = members.get(col)!.filter((n) => late.has(n.id)).sort(byName)
    if (!lates.length) continue
    const lane = `hop-${col}`
    const placed = [...positions.values()].filter((p) => p.lane === lane)
    const x = placed.length ? Math.max(...placed.map((p) => p.x)) : (left.get(col) ?? 0) + NODE_WIDTH / 2
    const bottom = placed.filter((p) => p.x === x).reduce((m, p) => Math.max(m, p.y), -ROW)
    lates.forEach((n, i) => positions.set(n.id, { x, y: bottom + (i + 1) * ROW, lane }))
  }
  return { positions, lanes }
}

// How far a line keeps from a card's middle when it is routed past it: half the tallest card (the
// internet's 68 px disc) and a margin.
export const ROUTE_CLEAR = 68 / 2 + 8

export interface Point {
  x: number
  y: number
}

/** A line's path when it must not run straight: its corners, where its word goes, and where the
 * word goes if that place is taken. */
export interface Route {
  points: Point[]
  mid: Point
  alts: Point[]
}

/** Each column band's card rows (the y of every card in it, sorted): what a routed line keeps
 * clear of. */
export function laneRows(positions: Map<string, Placed>): Map<string, number[]> {
  const rows = new Map<string, number[]>()
  for (const p of positions.values()) rows.set(p.lane, [...(rows.get(p.lane) ?? []), p.y])
  for (const ys of rows.values()) ys.sort((a, b) => a - b)
  return rows
}

/** Where a line crosses a column band it does not stop in: at its own height if no card is in the
 * way, else the nearest free gap between two cards, above the first or below the last; a tie goes
 * to the height the line is heading for. */
function corridor(ys: number[], y: number, heading: number): number {
  const free = (c: number) => ys.every((v) => Math.abs(v - c) >= ROUTE_CLEAR)
  if (free(y)) return y
  const options: number[] = []
  if (free(heading)) options.push(heading)
  for (let i = 1; i < ys.length; i++) if (ys[i]! - ys[i - 1]! >= 2 * ROUTE_CLEAR) options.push((ys[i]! + ys[i - 1]!) / 2)
  if (ys.length) options.push(ys[0]! - ROW / 2, ys[ys.length - 1]! + ROW / 2)
  options.sort((a, b) => Math.abs(a - y) - Math.abs(b - y) || Math.abs(a - heading) - Math.abs(b - heading))
  return options[0] ?? y
}

/**
 * The path of a line between two columns that would otherwise run behind a card (2026-11-17):
 * - its card is inside a wrapped band, away from the band's edge: the line runs flat to the edge
 *   (the staggered sub-columns leave it a free row);
 * - it skips one or more columns: it crosses each through a corridor (corridor()), flat inside the
 *   band.
 * It bends only in the gaps between bands. Null for the plain S between two neighbouring bands
 * whose cards sit at their edges, within one column, or when a band is unknown (a route's own
 * layout has none).
 */
export function lineRoute(s: Placed, t: Placed, lanes: Layout['lanes'], rows: Map<string, number[]>): Route | null {
  const dx = t.x - s.x
  if (Math.abs(dx) < 1) return null
  const dir = Math.sign(dx)
  const sb = lanes.find((l) => l.lane === s.lane)
  const tb = lanes.find((l) => l.lane === t.lane)
  if (!sb || !tb || sb === tb) return null
  const edge = (b: Layout['lanes'][number], side: number) => (side > 0 ? b.x + b.width : b.x)
  const from = edge(sb, dir)
  const to = edge(tb, -dir)
  if ((to - from) * dir <= 0) return null
  const lo = Math.min(from, to)
  const hi = Math.max(from, to)
  const between = lanes.filter((b) => b !== sb && b !== tb && b.x >= lo - 1 && b.x + b.width <= hi + 1).sort((a, b) => (a.x - b.x) * dir)
  const atEdge = (e: number, card: number) => Math.abs(e - card) < 1
  if (!between.length && atEdge(from, s.x + (dir * NODE_WIDTH) / 2) && atEdge(to, t.x - (dir * NODE_WIDTH) / 2)) return null
  const points: Point[] = [{ x: from, y: s.y }]
  let y = s.y
  let at = from
  let firstGap: number | null = null
  for (const b of between) {
    const near = edge(b, -dir)
    const far = edge(b, dir)
    const gap = (at + near) / 2
    firstGap ??= gap
    const crossing = corridor(rows.get(b.lane) ?? [], y, t.y)
    points.push({ x: gap, y }, { x: gap, y: crossing }, { x: near, y: crossing }, { x: far, y: crossing })
    y = crossing
    at = far
  }
  const gap = (at + to) / 2
  firstGap ??= gap
  points.push({ x: gap, y }, { x: gap, y: t.y }, { x: to, y: t.y })
  const path = points.filter((p, i) => i === 0 || p.x !== points[i - 1]!.x || p.y !== points[i - 1]!.y)
  return {
    points: path,
    mid: { x: gap, y: (y + t.y) / 2 },
    alts: [
      { x: (from + firstGap) / 2, y: s.y },
      { x: (gap + to) / 2, y: t.y },
    ],
  }
}

/** Where the canvas's camera stands, carried across a view switch: the zoom, and where the focus
 * card was in map coordinates, so it stays at the same place on screen. */
export interface Viewport {
  zoom: number
  pan: { x: number; y: number }
  anchor: { id: string; x: number; y: number } | null
}

export type Move = 'up' | 'down' | 'left' | 'right'

/** The arrow keys on the canvas: up and down within a column, left and right to the nearest node
 * of the next column that has one. With nothing selected, the focus (or the first node). */
export function moveSelection(positions: Map<string, Placed>, from: string | null, move: Move, focus: string | null): string | null {
  const all = [...positions.entries()]
  if (all.length === 0) return null
  const here = from != null ? positions.get(from) : undefined
  if (!here) return focus != null && positions.has(focus) ? focus : all[0]![0]
  if (move === 'up' || move === 'down') {
    const lane = all.filter(([, p]) => p.x === here.x).sort(([, a], [, b]) => a.y - b.y)
    const at = lane.findIndex(([id]) => id === from)
    const next = lane[at + (move === 'down' ? 1 : -1)]
    return next ? next[0] : from
  }
  const xs = [...new Set(all.map(([, p]) => p.x))].sort((a, b) => a - b)
  const x = xs[xs.indexOf(here.x) + (move === 'right' ? 1 : -1)]
  if (x === undefined) return from
  const lane = all.filter(([, p]) => p.x === x)
  lane.sort(([, a], [, b]) => Math.abs(a.y - here.y) - Math.abs(b.y - here.y) || a.y - b.y)
  return lane[0]![0]
}
