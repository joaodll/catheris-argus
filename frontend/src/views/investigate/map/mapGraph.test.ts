import { describe, expect, it } from 'vitest'
import { addMember, boundaryLabel, drawnEdges, emptyGraph, factOf, factsLine, graphNote, noFactNote, lineStyle, mergeGraph, nodeName, traceOf, worstOf, type MapEdge, type MapNode } from './mapGraph'

function node(uid: string, extra: Partial<MapNode> = {}): MapNode {
  return { uid, kind: 'resource', resource_id: 1, type: 'aws_lambda_function', name: uid, region: 'us-east-1', connection_id: 1, deleted_on: null, expanded: false, boundary: false, findings: {},
    vulnerabilities: null,
    attack_paths: null, ...extra }
}
let next = 1
function edge(source: string, target: string, origin = 'rule:x@1', type = 'ROUTES_TO'): MapEdge {
  return { id: next++, source_uid: source, target_uid: target, type, origin, attributes: {}, first_seen: '2026-10-01', last_seen: '2026-10-08' }
}

describe('the overlay facts', () => {
  const full = { findings: { prowler: { open: 3, worst: 'high' } }, vulnerabilities: { open: 12, worst: 'critical', exploitable: 2 }, attack_paths: { on: 4, entry: 1 } } as unknown as MapNode
  const bare = { findings: {}, vulnerabilities: null, attack_paths: null } as unknown as MapNode

  it('gives a card the chosen fact, in a severity colour only when it is a severity', () => {
    expect(factOf(full, null)).toEqual({ count: 3, worst: 'high' })
    expect(factOf(full, 'misconfigurations')).toEqual({ count: 3, worst: 'high' })
    expect(factOf(full, 'cves')).toEqual({ count: 12, worst: 'critical' })
    expect(factOf(full, 'exploits')).toEqual({ count: 2, worst: null })
    expect(factOf(full, 'paths')).toEqual({ count: 4, worst: null })
    expect(factOf(bare, 'cves').count).toBe(0)
    expect(factOf(null, 'paths').count).toBe(0)
  })

  it('says the facts in words, and nothing when there are none', () => {
    expect(factsLine(full)).toBe('12 CVEs · Exploit · On 4 paths')
    expect(factsLine(bare)).toBe('')
  })

  it('says when no card has the chosen fact, and what that means for CVEs', () => {
    expect(noFactNote(null, [bare])).toBeNull()
    expect(noFactNote('cves', [full, bare])).toBeNull()
    expect(noFactNote('cves', [bare])).toContain("scanner doesn't cover")
    expect(noFactNote('paths', [bare])).toBe('No open attack paths through the resources drawn.')
  })
})

describe('the graph note', () => {
  it('says when the map has not caught up with the scans', () => {
    expect(graphNote(null)).toBeNull()
    expect(graphNote({ behind: false, failed: false })).toBeNull()
    expect(graphNote({ behind: true, failed: false })?.kind).toBe('info')
    expect(graphNote({ behind: true, failed: true })?.kind).toBe('warn')
    expect(graphNote({ behind: false, failed: true })?.text).toContain('out of date')
  })
})

describe('Resource map graph state', () => {
  it('merges responses, keeps a node expanded once its neighbours were read', () => {
    const first = mergeGraph(emptyGraph(), { nodes: [node('a', { expanded: true }), node('b')], edges: [edge('a', 'b')], groups: [] })
    expect(first.added).toEqual(['a', 'b'])
    const second = mergeGraph(first.state, { nodes: [node('b', { expanded: true }), node('a'), node('c')], edges: [edge('b', 'c')] })
    expect(second.added).toEqual(['c'])
    expect(second.state.nodes.get('a')!.expanded).toBe(true)
    expect(second.state.nodes.get('b')!.expanded).toBe(true)
    expect(second.state.edges.size).toBe(2)
    expect(first.state.nodes.size).toBe(2) // a merge never changes the state it was given
  })

  it('stops at the cap and leaves out edges and groups whose ends are not shown', () => {
    const merged = mergeGraph(emptyGraph(), {
      nodes: [node('a'), node('b'), node('c')],
      edges: [edge('a', 'b'), edge('a', 'c')],
      groups: [{ id: 'g1', anchor_uid: 'c', direction: 'out', edge_type: 'IN_NETWORK', resource_type: 'aws_ec2_instance', count: 40 }],
    }, 2)
    expect(merged.capped).toBe(true)
    expect([...merged.state.nodes.keys()]).toEqual(['a', 'b'])
    expect(merged.state.edges.size).toBe(1)
    expect(merged.state.groups.size).toBe(0)
  })

  it('adds a group member with its edge', () => {
    const base = mergeGraph(emptyGraph(), { nodes: [node('vpc')], edges: [] }).state
    const added = addMember(base, { node: node('i-1'), edge: edge('i-1', 'vpc', 'rule:resource-in-network@1', 'IN_NETWORK') })
    expect(added.added).toEqual(['i-1'])
    expect(added.state.edges.size).toBe(1)
  })

  it('draws one line per connection, solid when a rule found it', () => {
    const state = mergeGraph(emptyGraph(), {
      nodes: [node('internet', { kind: 'internet' }), node('lb'), node('role')],
      edges: [edge('internet', 'lb', 'cloudfox', 'INTERNET_REACHABLE'), edge('internet', 'lb', 'rule:internet-entry@1', 'INTERNET_REACHABLE'), edge('lb', 'role', 'cloudfox', 'RUNS_AS')],
      groups: [{ id: 'g', anchor_uid: 'lb', direction: 'in', edge_type: 'MEMBER_OF', resource_type: null, count: 30 }],
    }).state
    const lines = drawnEdges(state)
    const both = lines.find((l) => l.source === 'internet')!
    expect(both.edges).toHaveLength(2)
    expect(both.families).toEqual(['cloudfox', 'rule'])
    expect(both.style).toBe('solid')
    expect(lines.find((l) => l.target === 'role')!.style).toBe('dashed')
    const group = lines.find((l) => l.group)!
    expect([group.source, group.target]).toEqual(['group:g', 'lb'])
  })

  it('styles lines by origin', () => {
    expect(lineStyle(['manual'])).toBe('dotted')
    expect(lineStyle(['cloudfox', 'manual'])).toBe('solid')
    expect(lineStyle(['cloudfox'])).toBe('dashed')
  })

  it('counts both tools for the badge and keeps the worst severity', () => {
    expect(worstOf(node('a', { findings: { prowler: { open: 3, worst: 'medium' }, cloudfox: { open: 1, worst: 'high' } } }))).toEqual({ worst: 'high', open: 4 })
    expect(worstOf(node('b'))).toEqual({ worst: null, open: 0 })
  })

  it('names pseudo-nodes in words', () => {
    expect(nodeName({ uid: 'internet', kind: 'internet', name: null })).toBe('Internet')
    expect(nodeName({ uid: 'admin:123', kind: 'admin', name: null })).toBe('Admin · 123')
    expect(nodeName({ uid: 'external:api.example.com', kind: 'external', name: null })).toBe('api.example.com')
  })
})

describe('boundary nodes', () => {
  const name = (id: number) => `conn-${id}`
  it('name the connection that owns them, else the account in their ARN', () => {
    expect(boundaryLabel(node('a', { boundary: true, connection_id: 4 }), name)).toBe('Other connection: conn-4')
    expect(boundaryLabel(node('arn:aws:iam::210987654321:root', { boundary: true, connection_id: null }), name)).toBe('Other account: 210987654321')
    expect(boundaryLabel(node('admin:210987654321', { kind: 'admin', connection_id: null }), name)).toBe('Other account: 210987654321')
  })
})

describe('Tracing a node', () => {
  // internet -> dns -> cf -> alb -> tg ; cf -> s3 ; other -> tg
  const graph = mergeGraph(emptyGraph(), {
    nodes: ['internet', 'dns', 'cf', 'alb', 's3', 'tg', 'other'].map((u) => node(u)),
    edges: [edge('internet', 'dns'), edge('dns', 'cf'), edge('cf', 'alb'), edge('cf', 's3'), edge('alb', 'tg'), edge('other', 'tg')],
  }).state
  const lines = drawnEdges(graph)

  it('keeps what reaches a node and what it reaches, not its siblings', () => {
    const trace = traceOf(lines, 'alb')
    expect([...trace.nodes].sort()).toEqual(['alb', 'cf', 'dns', 'internet', 'tg'])
    expect(trace.lines.size).toBe(4)
    expect(trace.nodes.has('s3')).toBe(false)
    // What feeds a node downstream is not part of its trace.
    expect(trace.nodes.has('other')).toBe(false)
  })
})
