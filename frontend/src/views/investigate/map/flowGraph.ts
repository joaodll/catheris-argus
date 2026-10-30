/**
 * Flow mode (docs/ui/screens.md, E11, Flow mode; ADR-0036): a flow from the API as the map's
 * graph, with each node's column and chips. The canvas, the List view and the panel then work
 * as in Explore.
 *
 * Two steps have no edge of their own and get a drawn line: a Route53 record that names the
 * entry ("RESOLVES", from the internet) and a function reaching data through its role ("USES",
 * the role in its attributes). Their ids are negative, so they never meet a real edge's id.
 */
import type { Schemas } from '@/api/client'
import type { GraphState, MapEdge, MapGroup, MapNode } from './mapGraph'

export type FlowDetail = Schemas['FlowDetail']
export type FlowChip = Schemas['FlowChip']

export interface FlowView {
  graph: GraphState
  // The column of every card: node uids and group card ids ("group:<id>").
  columns: Map<string, number>
  chips: Map<string, FlowChip[]>
  // The entry's column: the headers count steps from it.
  entryCol: number
}

export function flowView(flow: FlowDetail): FlowView {
  const nodes = new Map<string, MapNode>(flow.nodes.map((n) => [n.uid, n]))
  const byId = new Map<number, MapEdge>(flow.edges.map((e) => [e.id, e]))
  const edges = new Map<number, MapEdge>()
  const groups = new Map<string, MapGroup>()
  const columns = new Map<string, number>([['internet', 0]])
  let synthetic = 0
  let entryCol = 1
  for (const step of flow.steps) {
    if (step.kind === 'group') {
      const first = step.edge_ids.map((id) => byId.get(id)).find((e) => e)
      const id = `${step.source_uid}|out|${first?.type ?? 'ROUTES_TO'}|${step.group_type ?? ''}`
      groups.set(id, { id, anchor_uid: step.source_uid, direction: 'out', edge_type: first?.type ?? 'ROUTES_TO', resource_type: step.group_type, count: step.group_count ?? 0 })
      columns.set(`group:${id}`, step.col)
      continue
    }
    const target = step.target_uid!
    if (!columns.has(target) || columns.get(target)! < step.col) columns.set(target, step.col)
    if (target === flow.entry_uid) entryCol = step.col
    if (step.kind === 'edge') {
      for (const id of step.edge_ids) {
        const edge = byId.get(id)
        if (edge) edges.set(id, edge)
      }
      continue
    }
    synthetic -= 1
    edges.set(synthetic, {
      id: synthetic,
      source_uid: step.source_uid,
      target_uid: target,
      type: step.kind === 'dns' ? 'RESOLVES' : 'USES',
      origin: 'rule:flow@1',
      attributes: step.via_uid ? { via_role: step.via_uid } : {},
      first_seen: flow.as_of,
      last_seen: flow.as_of,
    })
  }
  const chips = new Map<string, FlowChip[]>()
  for (const chip of flow.chips) chips.set(chip.node_uid, [...(chips.get(chip.node_uid) ?? []), chip])
  return { graph: { nodes, edges, groups }, columns, chips, entryCol }
}

/** A flow column's header: Internet, then DNS when records name the entry, the entry, then the
 * steps after it. */
export function columnLabel(col: number, entryCol: number): string {
  if (col === 0) return 'Internet'
  if (col < entryCol) return 'DNS'
  if (col === entryCol) return 'Entry'
  return `Step ${col - entryCol}`
}

const CHIP_WORD: Record<FlowChip['kind'], string> = { security_group: 'SG', role: 'Role', waf: 'WAF' }
const CHIP_TITLE: Record<FlowChip['kind'], string> = { security_group: 'Security groups', role: 'Role', waf: 'WAF' }
const CHIP_ORDER: FlowChip['kind'][] = ['waf', 'role', 'security_group']

/** The chip row under a node: one short word per kind, with how many ("SG 2"), and the names
 * in its tooltip. */
export function chipSummary(chips: FlowChip[]): { kind: FlowChip['kind']; text: string; title: string }[] {
  const out = []
  for (const kind of CHIP_ORDER) {
    const names = chips.filter((c) => c.kind === kind).map((c) => c.name ?? c.chip_uid)
    if (names.length === 0) continue
    out.push({ kind, text: names.length > 1 ? `${CHIP_WORD[kind]} ${names.length}` : CHIP_WORD[kind], title: `${CHIP_TITLE[kind]}: ${names.join(', ')}` })
  }
  return out
}
