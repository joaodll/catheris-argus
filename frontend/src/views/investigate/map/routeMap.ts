/**
 * The Map's Attack Path view (ADR-0052 as amended 2026-11-15; spec W6 §11): one stored route's
 * chosen target, drawn from its own steps only, never from the map's neighbourhood. Pure
 * functions: the cards in walk order, each move as a line in one of the two reds (the way in
 * from outside, or a lateral move), the walk-made steps (a foothold, a login) that draw no line,
 * and the positions (left to right, wrapping into rows; one column on a narrow canvas).
 */
import { family, lineStyle, type LineStyle } from './mapGraph'
import { NODE_HEIGHT, NODE_WIDTH, LANE_GAP, type Layout, type Placed } from './mapLanes'
import { LEVEL_LABEL, LEVEL_MEANING, type StepLevel } from '../paths/routeClass'
import { moveWords, selfStepTitle, type StepNode, type StepOut } from '../paths/routeWords'

/** Which red a line is drawn in (W6 §11.2). */
export type RouteRole = 'entry' | 'lateral'

// The pseudo-nodes a route can get in from: the internet, anyone, an outside principal.
const OUTSIDE = new Set(['internet', 'any', 'external'])

/** A step that is a move from one card to another (a foothold or a login stands on one). */
export const isMove = (step: Pick<StepOut, 'source' | 'target'>): boolean => step.source.uid !== step.target.uid

/** The way in from outside is step 1 when it comes from the internet, anyone or an outsider;
 * every other move is lateral: resource to resource, account to account. */
export function stepRole(step: Pick<StepOut, 'n' | 'source'>): RouteRole {
  return step.n === 1 && OUTSIDE.has(step.source.kind) ? 'entry' : 'lateral'
}

/** What the view knows of accounts: a connection's AWS account, the connection that scans an
 * account (null: none does), and a connection's name. */
export interface Accounts {
  accountOf: (connectionId: number) => string | null
  connectionOf: (accountId: string) => number | null
  name: (connectionId: number) => string
}

const ARN_ACCOUNT = /^arn:aws[\w-]*:[^:]*:[^:]*:(\d{12}):/

/** The AWS account a card is in: its inventoried connection's, else the one its id names (an
 * ARN, an administrator, a store scoped to a connection). Null for the internet, anyone, and an
 * external host. */
export function nodeAccount(node: Pick<StepNode, 'uid' | 'kind' | 'connection_id'>, accounts: Accounts): string | null {
  if (node.kind === 'internet' || node.kind === 'external') return null
  if (node.connection_id != null) return accounts.accountOf(node.connection_id)
  if (node.kind === 'admin') return node.uid.replace(/^admin:/, '') || null
  if (node.kind === 'any') {
    const scoped = /@(\d+)$/.exec(node.uid)
    return scoped ? accounts.accountOf(Number(scoped[1])) : null
  }
  const arn = ARN_ACCOUNT.exec(node.uid)
  if (arn) return arn[1]!
  return /^\d{12}$/.test(node.uid) ? node.uid : null
}

/** An account by its connection's name, else by its id. */
function accountLabel(account: string, accounts: Accounts): string {
  const connection = accounts.connectionOf(account)
  return connection != null ? accounts.name(connection) : `account ${account}`
}

/** The accounts the moves cross into, by step n: a move whose two ends are in known, different
 * AWS accounts (W6 §11.3). The ends' own accounts, never the step's stored connection, which is
 * the connection that owns the edge row (a role's data access is owned by the role's account). */
export function crossings(steps: Pick<StepOut, 'n' | 'source' | 'target'>[], accounts: Accounts): Map<number, string> {
  const out = new Map<number, string>()
  for (const step of steps) {
    if (!isMove(step)) continue
    const from = nodeAccount(step.source, accounts)
    const to = nodeAccount(step.target, accounts)
    if (from && to && from !== to) out.set(step.n, accountLabel(to, accounts))
  }
  return out
}

// An account name on the canvas is cut here; the step list carries the whole name.
const ACCOUNT_MAX = 20
const short = (name: string): string => (name.length > ACCOUNT_MAX ? `${name.slice(0, ACCOUNT_MAX - 1)}…` : name)

export interface RouteLine {
  key: string
  n: number
  source: string
  target: string
  role: RouteRole
  // The origin's dash, as on every map line: solid for a rule, dashed for CloudFox, dotted manual.
  style: LineStyle
  // What the line says at rest: the move's short phrase, and the account it crosses into.
  words: string
  crossing: string | null
}

export interface SelfStep {
  n: number
  on: string
  // "Foothold · Assumed", "Login · Assumed": the tab above the card it stands on.
  tab: string
}

export interface RouteDrawing {
  // Each card once, in walk order.
  nodes: StepNode[]
  // A resource card's account, for its sub line: a connection's name, or "account <id>" for an
  // account no connection scans. Pseudo-nodes have none (an administrator's name says its own).
  accounts: Map<string, string>
  lines: RouteLine[]
  selfSteps: SelfStep[]
}

export const lineKey = (n: number): string => `step:${n}`

/** A card not in the inventory (an account's root, a principal) takes the connection that scans
 * the account its id names, so the card can say where it is. */
function withAccount(node: StepNode, accounts: Accounts): StepNode {
  if (node.kind !== 'resource' || node.connection_id != null) return node
  const account = nodeAccount(node, accounts)
  const connection = account ? accounts.connectionOf(account) : null
  return connection != null ? { ...node, connection_id: connection } : node
}

export function routeDrawing(steps: StepOut[], accounts: Accounts): RouteDrawing {
  const nodes = new Map<string, StepNode>()
  const lines: RouteLine[] = []
  const selfSteps: SelfStep[] = []
  const crossed = crossings(steps, accounts)
  for (const step of steps) {
    if (!nodes.has(step.source.uid)) nodes.set(step.source.uid, withAccount(step.source, accounts))
    if (!nodes.has(step.target.uid)) nodes.set(step.target.uid, withAccount(step.target, accounts))
    const level = LEVEL_LABEL[step.level as StepLevel] ?? step.level
    if (!isMove(step)) {
      selfSteps.push({ n: step.n, on: step.target.uid, tab: `${step.type === 'AUTHENTICATES' ? 'Login' : 'Foothold'} · ${level}` })
      continue
    }
    const crossing = crossed.get(step.n) ?? null
    const phrase = moveWords(step).short
    lines.push({
      key: lineKey(step.n),
      n: step.n,
      source: step.source.uid,
      target: step.target.uid,
      role: stepRole(step),
      style: lineStyle([family(step.origin)]),
      words: crossing ? `${phrase} · into ${short(crossing)}` : phrase,
      crossing,
    })
  }
  const named = new Map<string, string>()
  for (const node of nodes.values()) {
    if (node.kind !== 'resource') continue
    const account = nodeAccount(node, accounts)
    if (account) named.set(node.uid, accountLabel(account, accounts))
  }
  return { nodes: [...nodes.values()], accounts: named, lines, selfSteps }
}

/** The step a click on a card moves to: the first that ends there, else the first that leaves
 * from it (the route's first card), else step 1. */
export function stepAtCard(steps: Pick<StepOut, 'n' | 'source' | 'target'>[], uid: string): number {
  return steps.find((s) => s.target.uid === uid)?.n ?? steps.find((s) => s.source.uid === uid)?.n ?? 1
}

/** Where Leave route goes (§11.1): the current step's resource (its target), else its source,
 * else the route's entry. Null when none is an inventoried resource that still exists. */
export function leaveFocus(step: Pick<StepOut, 'source' | 'target'> | null, entry: Pick<StepNode, 'uid' | 'resource_id' | 'deleted_on'> | null): string | null {
  const usable = (n: Pick<StepNode, 'uid' | 'resource_id' | 'deleted_on'> | null | undefined) => (n && n.resource_id != null && !n.deleted_on ? n.uid : null)
  return usable(step?.target) ?? usable(step?.source) ?? usable(entry)
}

/** The live region's words for a step (§4.5, §11.5); `crossing` is the account it moves into. */
export function stepAnnouncement(step: StepOut, total: number, name: (n: StepNode) => string, crossing: string | null): string {
  const level = step.level as StepLevel
  const what = isMove(step) ? `${name(step.source)} to ${name(step.target)}: ${moveWords(step).short}` : selfStepTitle(step, name(step.target))
  const into = crossing ? ` Into ${crossing}.` : ''
  return `Step ${step.n} of ${total}. ${what}.${into} ${LEVEL_LABEL[level] ?? step.level}: ${LEVEL_MEANING[level] ?? ''}`.trim()
}

// ---- Layout (§11.4).
export const ROUTE_COLUMN = NODE_WIDTH + LANE_GAP // 376: room for a line's words between cards
export const ROUTE_ROW = NODE_HEIGHT + 160 // room for the badge and the words between rows
const ROUTE_PAD = 56 // the canvas's fit padding
const FULL_SIZE = 1 // a row is kept whole while the route still draws at 100 %

/** How many cards a row holds: the most that still draw at full size (100 %) when the route is
 * fitted, so a route that fits reads as one line; when none does, the count that draws it
 * largest on a canvas this size. */
export function perRow(count: number, width: number, height: number): number {
  let best = 1
  let bestZoom = -1
  let readable = 0
  for (let across = 1; across <= Math.max(count, 1); across++) {
    const rows = Math.ceil(count / across)
    const w = across * ROUTE_COLUMN - LANE_GAP
    const h = rows * ROUTE_ROW - (ROUTE_ROW - NODE_HEIGHT)
    const zoom = Math.min((width - 2 * ROUTE_PAD) / w, (height - 2 * ROUTE_PAD) / h)
    if (zoom >= FULL_SIZE) readable = across
    if (zoom >= bestZoom - 1e-9) {
      best = across
      bestZoom = zoom
    }
  }
  return readable || best
}

/** Positions in walk order, in rows of `perRow` cards, every row left to right. The lanes are
 * empty: the Attack Path view names no column. */
export function routeLayout(ids: string[], width: number, height: number): Layout {
  const positions = new Map<string, Placed>()
  const across = perRow(ids.length, width, height)
  ids.forEach((id, i) => {
    const row = Math.floor(i / across)
    const col = i % across
    positions.set(id, { x: col * ROUTE_COLUMN, y: row * ROUTE_ROW, lane: `row-${row}` })
  })
  return { positions, lanes: [] }
}

/** A line's shape between two placed cards: straight along a row or a column; between rows, down
 * from the source, left through the gap, and down into the target. The control points are
 * Cytoscape's (weights along source-target, distances along its normal). `mid` is the badge's
 * place; the words go 20 px below it. */
export function routeBend(s: { x: number; y: number }, t: { x: number; y: number }): { weights: number[]; distances: number[]; mid: { x: number; y: number } } {
  const dx = t.x - s.x
  const dy = t.y - s.y
  const length2 = dx * dx + dy * dy
  const straight = { weights: [0.5], distances: [0], mid: { x: (s.x + t.x) / 2, y: (s.y + t.y) / 2 } }
  if (length2 === 0 || Math.abs(dy) < 1 || Math.abs(dx) < 1) return straight
  const length = Math.sqrt(length2)
  const gap = s.y + (dy > 0 ? 1 : -1) * (ROUTE_ROW / 2)
  const points = [
    { x: s.x, y: gap },
    { x: t.x, y: gap },
  ]
  return {
    weights: points.map((p) => ((p.x - s.x) * dx + (p.y - s.y) * dy) / length2),
    distances: points.map((p) => ((p.x - s.x) * -dy + (p.y - s.y) * dx) / length),
    mid: { x: (s.x + t.x) / 2, y: gap },
  }
}
