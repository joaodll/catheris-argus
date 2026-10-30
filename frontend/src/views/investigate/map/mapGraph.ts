/**
 * What the Resource map holds (docs/ui/screens.md, E11): the focus neighbourhood, plus what
 * Expand and group members added, merged one response at a time and never past 500 nodes (the
 * most the canvas draws, as the API's cap). Pure functions over immutable maps: a merge returns
 * a new state.
 */
import type { Schemas } from '@/api/client'
import { SEVERITIES, type Severity } from '@/views/overview/severity'

export type MapNode = Schemas['MapNode']
export type MapEdge = Schemas['MapEdge']
export type MapGroup = Schemas['MapGroup']

export const MAX_NODES = 500

/** Why a boundary node is not expanded: whose resource it is. An inventoried resource names its
 * connection; anything else names the account in its ARN (or `admin:<account>`). */
export function boundaryLabel(node: MapNode, connectionName: (id: number) => string): string {
  if (node.connection_id != null) return `Other connection: ${connectionName(node.connection_id)}`
  const account = node.uid.startsWith('admin:') ? node.uid.slice(6) : node.uid.split(':')[4]
  return account ? `Other account: ${account}` : 'Other account'
}

/** What the map's panel shows: a node, a group (by its id) or a drawn line (by its key). */
export type Selection = { kind: 'node'; id: string } | { kind: 'group'; id: string } | { kind: 'edge'; key: string }

export interface GraphState {
  nodes: ReadonlyMap<string, MapNode>
  edges: ReadonlyMap<number, MapEdge>
  groups: ReadonlyMap<string, MapGroup>
}

export function emptyGraph(): GraphState {
  return { nodes: new Map(), edges: new Map(), groups: new Map() }
}

export interface Merged {
  state: GraphState
  // The nodes that were not on the map before.
  added: string[]
  // Some nodes were left out: the map holds MAX_NODES.
  capped: boolean
}

/** Adds a response's nodes, edges and groups. A node already shown keeps "expanded" once its
 * neighbours were read. An edge or group whose ends are not on the map is left out. */
export function mergeGraph(
  state: GraphState,
  response: { nodes: MapNode[]; edges: MapEdge[]; groups?: MapGroup[] },
  max: number = MAX_NODES,
): Merged {
  const nodes = new Map(state.nodes)
  const added: string[] = []
  let capped = false
  for (const node of response.nodes) {
    const known = nodes.get(node.uid)
    if (known) {
      nodes.set(node.uid, { ...known, ...node, expanded: known.expanded || node.expanded })
    } else if (nodes.size < max) {
      nodes.set(node.uid, node)
      added.push(node.uid)
    } else {
      capped = true
    }
  }
  const edges = new Map(state.edges)
  for (const edge of response.edges) {
    if (nodes.has(edge.source_uid) && nodes.has(edge.target_uid)) edges.set(edge.id, edge)
  }
  const groups = new Map(state.groups)
  for (const group of response.groups ?? []) {
    if (nodes.has(group.anchor_uid)) groups.set(group.id, group)
  }
  return { state: { nodes, edges, groups }, added, capped }
}

/** A group member picked in the panel: the member and the edge that links it to the anchor. */
export function addMember(state: GraphState, member: { node: MapNode; edge: MapEdge }, max: number = MAX_NODES): Merged {
  return mergeGraph(state, { nodes: [member.node], edges: [member.edge] }, max)
}

export const groupNodeId = (group: MapGroup): string => `group:${group.id}`

export type Family = 'rule' | 'cloudfox' | 'manual' | 'probe'
export type LineStyle = 'solid' | 'dashed' | 'dotted'

/** An edge's origin family: "rule:<id>@<version>" is a rule. */
export function family(origin: string): Family {
  if (origin.startsWith('rule:')) return 'rule'
  return origin === 'cloudfox' || origin === 'manual' || origin === 'probe' ? origin : 'rule'
}

/** Solid when a rule found it, dashed when only CloudFox did, dotted when only a person did. */
export function lineStyle(families: Family[]): LineStyle {
  const only = (f: Family) => families.length > 0 && families.every((x) => x === f)
  if (only('cloudfox')) return 'dashed'
  if (only('manual')) return 'dotted'
  return 'solid'
}

/** One line on the canvas: every edge with the same ends and type (a rule and CloudFox finding
 * the same connection draw one solid line; the panel lists both origins). */
export interface DrawnEdge {
  key: string
  source: string
  target: string
  type: string
  edges: MapEdge[]
  families: Family[]
  style: LineStyle
  // The line to a group node, which stands for the group's edges.
  group: MapGroup | null
}

export function drawnEdges(state: GraphState): DrawnEdge[] {
  const lines = new Map<string, DrawnEdge>()
  for (const edge of state.edges.values()) {
    const key = `${edge.source_uid}|${edge.target_uid}|${edge.type}`
    const line = lines.get(key) ?? { key, source: edge.source_uid, target: edge.target_uid, type: edge.type, edges: [], families: [], style: 'solid', group: null }
    line.edges.push(edge)
    const f = family(edge.origin)
    if (!line.families.includes(f)) line.families.push(f)
    lines.set(key, line)
  }
  for (const line of lines.values()) {
    line.families.sort()
    line.edges.sort((a, b) => a.id - b.id)
    line.style = lineStyle(line.families)
  }
  for (const group of state.groups.values()) {
    const node = groupNodeId(group)
    const [source, target] = group.direction === 'out' ? [group.anchor_uid, node] : [node, group.anchor_uid]
    lines.set(node, { key: node, source, target, type: group.edge_type, edges: [], families: [], style: 'solid', group })
  }
  return [...lines.values()]
}

/** A node's open findings over both tools: the worst severity and the count (no badge at 0). */
export function worstOf(node: MapNode): { worst: Severity | null; open: number } {
  let open = 0
  let worst: Severity | null = null
  for (const t of Object.values(node.findings)) {
    open += t.open
    const r = SEVERITIES.indexOf(t.worst as Severity)
    if (t.open > 0 && r >= 0 && (worst === null || r < SEVERITIES.indexOf(worst))) worst = SEVERITIES[r]!
  }
  return { worst: open > 0 ? worst : null, open }
}

/** 0 for critical … 4 for informational, 5 for none: nodes stack worst first. */
export function worstRank(node: MapNode): number {
  const { worst } = worstOf(node)
  return worst ? SEVERITIES.indexOf(worst) : SEVERITIES.length
}

/** How a node reads in words: its name, else its pseudo-node label, else its uid. */
export function nodeName(node: Pick<MapNode, 'uid' | 'kind' | 'name'>): string {
  if (node.kind === 'internet') return 'Internet'
  if (node.kind === 'admin') return `Admin · ${node.uid.replace(/^admin:/, '')}`
  if (node.kind === 'external') return node.uid.replace(/^external:/, '')
  if (node.kind === 'any') return `Any ${node.uid.replace(/^any:/, '')} resource`
  return node.name || node.uid
}

/** How many edges touch a node (List view, Connections column). */
export function degree(state: GraphState, uid: string): number {
  let n = 0
  for (const e of state.edges.values()) if (e.source_uid === uid || e.target_uid === uid) n++
  return n
}

/** A node's trace (docs/ui/screens.md, E11, Interaction): the node, everything the drawn lines
 * reach it from and everything it reaches, with the lines between them. */
export function traceOf(lines: Pick<DrawnEdge, 'key' | 'source' | 'target'>[], id: string): { nodes: Set<string>; lines: Set<string> } {
  const nodes = new Set([id])
  const keys = new Set<string>()
  for (const [from, to] of [['target', 'source'], ['source', 'target']] as const) {
    const queue = [id]
    const seen = new Set([id])
    while (queue.length) {
      const at = queue.shift()!
      for (const line of lines) {
        if (line[from] !== at) continue
        keys.add(line.key)
        nodes.add(line[to])
        if (!seen.has(line[to])) {
          seen.add(line[to])
          queue.push(line[to])
        }
      }
    }
  }
  return { nodes, lines: keys }
}

/** The shortest chain from the internet to a node along the drawn lines (Flow mode's "Path from
 * the internet"), each step with the line that reached it; null when none leads there. */
export function pathFromInternet(lines: DrawnEdge[], id: string): { uid: string; line: DrawnEdge | null }[] | null {
  const via = new Map<string, DrawnEdge | null>([['internet', null]])
  const queue = ['internet']
  while (queue.length && !via.has(id)) {
    const at = queue.shift()!
    for (const line of lines) {
      if (line.source !== at || via.has(line.target)) continue
      via.set(line.target, line)
      queue.push(line.target)
    }
  }
  if (!via.has(id)) return null
  const out: { uid: string; line: DrawnEdge | null }[] = []
  for (let at: string | undefined = id; at != null; ) {
    const line: DrawnEdge | null = via.get(at) ?? null
    out.unshift({ uid: at, line })
    at = line?.source
  }
  return out
}
