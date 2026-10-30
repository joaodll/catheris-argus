/**
 * The Resource map's columns (docs/ui/screens.md, E11, The canvas): the chain in the order traffic
 * and access follow it, one column per hop (argus_v12: "follow the exact resource chain
 * sequence, no separation by column type"). Explore counts hops from the chosen resource,
 * sources to its left and targets to its right; Flow mode numbers its steps from the internet
 * (flowLayout). Positions are computed here and handed to Cytoscape's preset layout (ADR-0033):
 * the same view always places a node in the same spot.
 */
import type { IconName } from '@/components/icons'
import { typeGroupOf } from '@/views/overview/assetTypes'

export const LANE_WIDTH = 178
export const LANE_GAP = 28
export const ROW = 70
export const NODE_WIDTH = 178
export const NODE_HEIGHT = 46

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

const GROUP_ICON: Record<string, IconName> = { Compute: 'chip', Storage: 'database', Network: 'nodes', Identity: 'key', Other: 'cube' }
/** A node's icon disc (screens.md, E11): its type group's colour and glyph, the Overview's
 * groups. A group card keeps the glyph in the neutral colour; an outside host is "external". */
export function typeDisc(kind: NodeKind | string, type: string | null): { color: string; icon: IconName } {
  if (kind === 'internet') return { color: 'var(--text-2)', icon: 'globe' }
  if (kind === 'external' || kind === 'any') return { color: 'var(--text-3)', icon: 'external' }
  if (!type) return { color: 'var(--type-other)', icon: 'cube' }
  const group = typeGroupOf(type)
  return { color: kind === 'group' ? 'var(--type-other)' : group.color, icon: GROUP_ICON[group.name] ?? 'cube' }
}

export function typeLabel(type: string | null): string {
  if (!type) return 'Not in the inventory'
  for (const [pattern, label] of TYPE_LABELS) if (pattern.test(type)) return label
  return type.replace(/^aws_/, '').replace(/_/g, ' ')
}

export interface LaidNode {
  id: string
  kind: NodeKind
  type: string | null
  name: string
  // 0 critical … 4 informational, 5 none: worst first.
  rank: number
}

export interface Placed {
  x: number
  y: number
  // A hop column in Explore ("hop-<n>"); a flow column ("col-<n>") in Flow mode.
  lane: string
}

export interface Layout {
  positions: Map<string, Placed>
  // The columns that hold a node, left to right, each with its header and its band's left edge.
  lanes: { lane: string; label: string; x: number }[]
}

interface Link {
  source: string
  target: string
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

/**
 * Explore: one column per hop (hopColumns), LANE_WIDTH wide with LANE_GAP between, empty columns
 * hidden. In a column, nodes ROW apart, worst first then by name; the focus sits at y = 0 in the
 * middle of its column, every other column is centred on 0.
 */
export function layout(nodes: LaidNode[], edges: Link[], focus: string | null): Layout {
  const cols = hopColumns(
    nodes.map((n) => n.id),
    edges,
    focus,
  )
  const focused = focus != null && cols.has(focus)
  const members = new Map<number, LaidNode[]>()
  for (const n of nodes) {
    const col = cols.get(n.id)!
    members.set(col, [...(members.get(col) ?? []), n])
  }
  const shown = [...members.keys()].sort((a, b) => a - b)
  const lanes = shown.map((col, at) => ({ lane: `hop-${col}`, label: hopLabel(col, focused), x: at * (LANE_WIDTH + LANE_GAP) }))
  const positions = new Map<string, Placed>()
  shown.forEach((col, at) => {
    const list = [...members.get(col)!].sort((a, b) => a.rank - b.rank || a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
    const focusAt = list.findIndex((n) => n.id === focus)
    let origin: number
    if (focusAt >= 0) {
      const [f] = list.splice(focusAt, 1)
      const middle = Math.floor(list.length / 2)
      list.splice(middle, 0, f!)
      origin = middle
    } else {
      origin = (list.length - 1) / 2
    }
    const x = at * (LANE_WIDTH + LANE_GAP) + LANE_WIDTH / 2
    list.forEach((n, row) => positions.set(n.id, { x, y: (row - origin) * ROW, lane: `hop-${col}` }))
  })
  return { positions, lanes }
}

/**
 * Flow mode (ADR-0036): one column per step from the internet, as the API numbers them, empty
 * columns hidden. In a column, nodes ROW apart, worst first then by name, centred on 0.
 */
export function flowLayout(nodes: LaidNode[], columns: ReadonlyMap<string, number>, label: (col: number) => string): Layout {
  const members = new Map<number, LaidNode[]>()
  for (const n of nodes) {
    const col = columns.get(n.id)
    if (col !== undefined) members.set(col, [...(members.get(col) ?? []), n])
  }
  const shown = [...members.keys()].sort((a, b) => a - b)
  const lanes = shown.map((col, at) => ({ lane: `col-${col}`, label: label(col), x: at * (LANE_WIDTH + LANE_GAP) }))
  const positions = new Map<string, Placed>()
  shown.forEach((col, at) => {
    const list = [...members.get(col)!].sort((a, b) => a.rank - b.rank || a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
    const origin = (list.length - 1) / 2
    const x = at * (LANE_WIDTH + LANE_GAP) + LANE_WIDTH / 2
    list.forEach((n, row) => positions.set(n.id, { x, y: (row - origin) * ROW, lane: `col-${col}` }))
  })
  return { positions, lanes }
}

export type Move = 'up' | 'down' | 'left' | 'right'

/** The arrow keys on the canvas: up and down within a lane, left and right to the nearest node
 * of the next lane that has one. With nothing selected, the focus (or the first node). */
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
