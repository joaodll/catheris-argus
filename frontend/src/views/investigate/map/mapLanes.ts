/**
 * The Resource map's columns (ADR-0051): the chain in the order traffic and access follow it,
 * one column per hop, counted in hops from the chosen resource, sources to its left and targets
 * to its right. Positions are computed here and handed to Cytoscape's preset layout: the same
 * view always places a node in the same spot.
 *
 * The sizes are the spec's (palace, frontend/f3152e04): the owner asked for more space between
 * the cards than the first map had (178 x 46 cards, 120 between columns, 70 from row to row).
 */
import type { IconName } from '@/components/icons'
import { resourceGlyph } from '../resourceGlyph'

export const NODE_WIDTH = 208
export const NODE_HEIGHT = 56
export const LANE_WIDTH = NODE_WIDTH
// Room for a line's word at its midpoint, clear of the cards on both sides. The longest word,
// "is administrator", is about 90 px.
export const LANE_GAP = 168
// From one card's middle to the next: 40 px between cards.
export const ROW = 96
// How far above the highest card a column's name sits.
export const LANE_NAME_RISE = 64

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
 * One column per hop (hopColumns), LANE_WIDTH wide with LANE_GAP between, empty columns hidden.
 * In a column, nodes ROW apart, by name: a card's place never depends on a security fact, so
 * the Infrastructure and Security views draw the same picture. The focus sits at y = 0 in the
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
    const list = [...members.get(col)!].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
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
