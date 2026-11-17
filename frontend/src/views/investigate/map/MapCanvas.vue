<script setup lang="ts">
/**
 * The Map's canvas (ADR-0051; specs in the palace, frontend/f3152e04, round M frontend/4f5295ad).
 *
 * Cytoscape.js draws the edges and handles pan, zoom and edge hits. The cards and the column names
 * are an HTML layer that follows its viewport: a card needs an icon tile, two type sizes and the
 * design tokens, which a canvas label cannot hold. A dot grid moves with the map, hovering a card
 * traces what reaches it and what it reaches, and an overview sits in the corner. Positions come
 * from mapLanes (one column per hop, left to right; Cytoscape's preset layout), so the same view
 * always places a card in the same spot.
 *
 * In the Infrastructure view a card says what a resource is and where, never a security fact:
 * the map as a network and architecture diagram. In the Security view (`map`, card B; spec
 * frontend/4242ef35) a card also carries a count pill of open misconfigurations in the worst
 * severity's colour, a frame and its word for Critical or High, and marks for internet
 * reachable, open vulnerabilities and a public exploit (mapFacts.ts), and the security lines are
 * heavier than the connections. Positions never depend on a fact; a view switch keeps the focus
 * card where it is on screen (a card only a security line reaches can add a row).
 *
 * Each line says what it is in plain words (edgeWords.ts) at its midpoint, in the gap between
 * columns, at one size on screen whatever the zoom. The words are in the HTML layer too:
 * Cytoscape paints an edge's label with its edge, so the next line would cross it. At rest
 * every label shows while card text does (zoom >= 0.55) and no two overlap: the hovered line
 * wins, then a lit trace, then lines touching the focus, then reading order; a hidden one
 * shows when hovered.
 *
 * The Attack Path view (`route`; W6 §11) draws one stored route's chosen target and nothing else:
 * its cards in walk order (routeMap.ts), every move in one of the two reds (the way in from
 * outside, or a lateral move; the origin keeps its dash), a numbered badge at each line's middle
 * and its words below it, a tab over a card a foothold or a login stands on, and the player's
 * current step lit. A card click moves the player (MapView), it opens no panel.
 *
 * The canvas is one focusable region: the arrow keys move a keyboard position between nodes,
 * Enter selects, E expands, C collapses, F makes the focus, Esc clears. The List view is the accessible
 * equivalent of the whole picture.
 */
import cytoscape, { type Core, type EdgeSingular, type ElementDefinition } from 'cytoscape'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import AppIcon from '@/components/AppIcon.vue'
import type { IconName } from '@/components/icons'
import { regionLabel } from '../labels'
import { edgeWord } from '../edgeWords'
import CountPill from './CountPill.vue'
import { SECURITY_EDGE_TYPES, factLines, factsOf, marksOf, pillCount, worstOf, type Marks } from './mapFacts'
import type { Severity } from '@/views/overview/severity'
import type { MapKind } from './mapQuery'
import { boundaryLabel, drawnEdges, groupNodeId, nodeName, traceOf, type GraphState, type MapGroup, type MapNode, type Selection } from './mapGraph'
import { LANE_NAME_RISE, NODE_HEIGHT, NODE_WIDTH, cardGlyph, flatRun, layout, moveSelection, typeLabel, type LaidNode, type Move, type NodeKind, type Placed, type Viewport } from './mapLanes'
import { lineKey, routeBend, routeLayout, type RouteDrawing, type RouteLine } from './routeMap'
import { SEVERITY_LABEL } from '@/views/overview/severity'
import { resolvedTheme } from '@/composables/useTheme'

const props = defineProps<{
  graph: GraphState
  focus: string | null
  selection: Selection | null
  connectionName: (id: number) => string
  map?: MapKind
  // The cards a person expanded (Collapse undoes them).
  collapsible?: ReadonlySet<string>
  // The camera to open at instead of the first view (a view switch on the same focus).
  initialViewport?: Viewport | null
  // The Attack Path view: the route's drawing, the player's step (n) and the route's title.
  route?: { drawing: RouteDrawing; current: number; title: string } | null
}>()
const emit = defineEmits<{ select: [selection: Selection | null]; expand: [uid: string]; collapse: [uid: string]; focusHere: [uid: string] }>()
const security = computed(() => props.map === 'security')
const routed = computed(() => props.route != null)
// The drawing alone: a step change gives a new `route` with the same drawing, and must not redraw
// the lines (the current step's line fades in on its own element).
const routeDraw = computed(() => props.route?.drawing ?? null)
const routeLines = computed(() => new Map((routeDraw.value?.lines ?? []).map((l) => [l.key, l])))

/** One card on the canvas: a node of the graph, or a group standing for many. */
interface Card {
  id: string
  kind: NodeKind
  node: MapNode | null
  group: MapGroup | null
  name: string
  type: string | null
  typeLabel: string
  // The glyph on its tile: the resource type's.
  icon: IconName
  w: number
  h: number
  // The Security view's card B: the pill's count and its severity's token, the marks, the facts
  // in words (tooltip, announcement). Null or empty on the Infrastructure view and on pseudo-nodes.
  pill: { count: string; severity: Severity } | null
  marks: Marks | null
  facts: string[]
}

const SIZE: Record<NodeKind, [number, number]> = {
  resource: [NODE_WIDTH, NODE_HEIGHT],
  external: [NODE_WIDTH, NODE_HEIGHT],
  any: [NODE_WIDTH, NODE_HEIGHT],
  group: [NODE_WIDTH, NODE_HEIGHT],
  internet: [68, 68], // a 64 px disc inside
  admin: [52, 52],
}

function plural(label: string, n: number): string {
  if (n === 1) return label
  if (/[^aeiou]y$/.test(label)) return `${label.slice(0, -1)}ies`
  return /s$/.test(label) ? `${label}es` : `${label}s`
}

const cards = computed<Card[]>(() => {
  const out: Card[] = []
  for (const node of props.graph.nodes.values()) {
    const kind = node.kind as NodeKind
    const [w, h] = SIZE[kind]
    const what = node.boundary ? boundaryLabel(node, props.connectionName) : kind === 'external' ? 'Not in the inventory' : kind === 'any' ? 'Wildcard grant (*)' : typeLabel(node.type)
    const facts = security.value ? factsOf(node) : null
    const count = pillCount(facts)
    const worst = worstOf(facts)
    const marks = marksOf(facts)
    out.push({
      id: node.uid,
      kind,
      node,
      group: null,
      name: nodeName(node),
      type: node.type,
      typeLabel: [what, routeDraw.value?.accounts.get(node.uid) ?? null, node.deleted_on ? `removed ${node.deleted_on}` : null]
        .filter(Boolean)
        .join(' · '),
      icon: cardGlyph(kind, node.type),
      w,
      h,
      pill: count && worst ? { count, severity: worst } : null,
      marks: marks.internet || marks.vulnerable || marks.exploit ? marks : null,
      facts: facts ? factLines(facts, node.connection_id != null ? props.connectionName(node.connection_id) : 'its account') : [],
    })
  }
  for (const group of props.graph.groups.values()) {
    const anchor = props.graph.nodes.get(group.anchor_uid)
    out.push({
      id: groupNodeId(group),
      kind: 'group',
      node: null,
      group,
      name: plural(group.resource_type ? typeLabel(group.resource_type) : 'resource', group.count),
      type: group.resource_type,
      typeLabel: `${edgeWord(group.edge_type)} ${group.direction === 'out' ? '←' : '→'} ${anchor ? nodeName(anchor) : group.anchor_uid}`,
      icon: cardGlyph('group', group.resource_type),
      w: NODE_WIDTH,
      h: NODE_HEIGHT,
      pill: null,
      marks: null,
      // A group's members are unbounded: their facts are in the panel's member table.
      facts: security.value ? ['Open the group to see each member'] : [],
    })
  }
  return out
})
const byId = computed(() => new Map(cards.value.map((c) => [c.id, c])))
// The Attack Path view's lines are the route's moves, never the graph's edges.
const lines = computed(() =>
  routeDraw.value
    ? routeDraw.value.lines.map((l: RouteLine) => ({ key: l.key, source: l.source, target: l.target, type: '', edges: [], families: [], style: l.style, layer: null, group: null }))
    : drawnEdges(props.graph),
)

// The canvas's shape when the graph was laid out: a resize re-fits, it never lays out again, so
// the cards stay where they are (spec §3.2).
const aspect = ref(16 / 9)
const width = ref(1200)
const laid = computed(() => {
  // A route: walk order, in the rows that draw it largest on this canvas (§11.4).
  if (routed.value) return routeLayout(cards.value.map((c) => c.id), width.value, width.value / aspect.value)
  const laidNodes = cards.value.map<LaidNode>((c) => ({ id: c.id, kind: c.kind, type: c.type, name: c.name }))
  return layout(
    laidNodes,
    lines.value.map((l) => ({ source: l.source, target: l.target, layer: l.layer, type: l.type })),
    props.focus,
    aspect.value,
  )
})
function measureAspect(): void {
  const el = region.value
  if (el && el.clientWidth > 0 && el.clientHeight > 0) {
    aspect.value = el.clientWidth / el.clientHeight
    width.value = el.clientWidth
  }
}
function sizeOf(card: Card): [number, number] {
  return [card.w, card.h]
}
const laneLabel = computed(() => new Map(laid.value.lanes.map((l) => [l.lane, l.label])))
// Security view: a Critical or High worst misconfiguration frames the card in its colour, with
// its word on the frame (never the colour alone).
function frameOf(card: Card): 'critical' | 'high' | null {
  const s = card.pill?.severity
  return s === 'critical' || s === 'high' ? s : null
}

// ---- What is lit: the selection's trace (what reaches it and what it reaches) or, with
// nothing selected, the hovered card's trace.
const selectedNode = computed(() => (props.selection?.kind === 'node' ? props.selection.id : props.selection?.kind === 'group' ? `group:${props.selection.id}` : null))
const hovered = ref<string | null>(null)
const lit = computed<{ nodes: Set<string>; lines: Set<string> } | null>(() => {
  // The Attack Path view lights the player's step only: its line, or the card it stands on.
  if (props.route) {
    const line = routeLines.value.get(lineKey(props.route.current))
    if (line) return { nodes: new Set([line.source, line.target]), lines: new Set([line.key]) }
    const self = props.route.drawing.selfSteps.find((x) => x.n === props.route!.current)
    return self ? { nodes: new Set([self.on]), lines: new Set() } : null
  }
  const sel = props.selection
  if (sel?.kind === 'edge') {
    const line = lines.value.find((l) => l.key === sel.key)
    return line ? { nodes: new Set([line.source, line.target]), lines: new Set([line.key]) } : null
  }
  if (selectedNode.value) return traceOf(lines.value, selectedNode.value)
  if (hovered.value && byId.value.has(hovered.value)) return traceOf(lines.value, hovered.value)
  return null
})
function dimmed(id: string): boolean {
  // Every card of a route stays in full: the whole route is the attacker's path.
  if (routed.value) return false
  return lit.value != null && !lit.value.nodes.has(id) && id !== props.focus
}

// ---- Cytoscape: edges, and invisible node shapes for their ends.
const container = ref<HTMLElement | null>(null)
const region = ref<HTMLElement | null>(null)
const cy = shallowRef<Core | null>(null)
const pan = ref({ x: 0, y: 0 })
const zoom = ref(1)
const size = ref({ w: 0, h: 0 })
let known = new Set<string>() // the cards drawn, to find what a response added
const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

/** Control points for a curve between two points: an S that leaves and enters horizontally
 * between columns, an arc to the right within one. Cytoscape takes them as weights along the
 * source-target line and distances along its normal (-dy, dx) / length. */
interface Bend {
  weights: number[]
  distances: number[]
  // Where the word goes: the middle of the S between columns, the arc's apex in a column.
  mid: { x: number; y: number }
  // Where it goes if the middle is taken (a card, another word): on the S's horizontal parts, a
  // quarter of the way from each end. None for an arc.
  alts: { x: number; y: number }[]
}
function bend(s: { x: number; y: number }, t: { x: number; y: number }, run: { from: number; to: number } | null = null): Bend {
  const dx = t.x - s.x
  const dy = t.y - s.y
  const length2 = dx * dx + dy * dy
  if (length2 === 0) return { weights: [0.5], distances: [0], mid: { ...s }, alts: [] }
  const length = Math.sqrt(length2)
  const arc = Math.abs(dx) < 1
  // From a card inside a wrapped column (flatRun): flat to the band's edge, the bend in the gap,
  // flat again. Cytoscape draws a chain of curves through the midpoints of the control points,
  // so the first and last pieces, whose points share a row, are straight.
  const gap = run ? (run.from + run.to) / 2 : s.x + dx / 2
  const points = arc
    ? [{ x: s.x + NODE_WIDTH * 0.4 + Math.abs(dy) * 0.15, y: (s.y + t.y) / 2 }]
    : run
      ? [
          { x: run.from, y: s.y },
          { x: gap, y: s.y },
          { x: gap, y: t.y },
          { x: run.to, y: t.y },
        ]
      : [
          { x: gap, y: s.y },
          { x: gap, y: t.y },
        ]
  const mid = arc ? { x: 0.25 * s.x + 0.5 * points[0]!.x + 0.25 * t.x, y: (s.y + t.y) / 2 } : { x: gap, y: (s.y + t.y) / 2 }
  return {
    weights: points.map((p) => ((p.x - s.x) * dx + (p.y - s.y) * dy) / length2),
    distances: points.map((p) => ((p.x - s.x) * -dy + (p.y - s.y) * dx) / length),
    mid,
    alts: arc
      ? []
      : run
        ? [
            { x: (run.from + gap) / 2, y: s.y },
            { x: (gap + run.to) / 2, y: t.y },
          ]
        : [
            { x: s.x + dx * 0.25, y: s.y },
            { x: s.x + dx * 0.75, y: t.y },
          ],
  }
}

// ---- Line labels: one size on screen, never on top of each other.
const LABEL_PX = 11
const LABEL_MIN_ZOOM = 0.55 // the zoom below which card text hides (`far`)
const CHAR_PX = 6.2 // Inter at 11 px, a lower-case word's average advance
const LABEL_PAD = 4
interface LineWord {
  key: string
  text: string
  x: number
  y: number
  tone: 'rest' | 'hover' | 'lit'
  // A security line's word (the Security view): stronger at rest.
  sec: boolean
  // A route line not reached yet (the Attack Path view).
  ahead?: boolean
}
const words = shallowRef<LineWord[]>([])
// A route line's words sit this far below its badge.
const ROUTE_WORDS_BELOW = 20
function elements(): ElementDefinition[] {
  const positions = laid.value.positions
  const nodes: ElementDefinition[] = cards.value.map((c) => {
    const [w, h] = sizeOf(c)
    return {
      group: 'nodes',
      data: { id: c.id, w, h, shape: c.kind === 'internet' ? 'ellipse' : c.kind === 'admin' ? 'diamond' : 'round-rectangle' },
      position: { x: positions.get(c.id)!.x, y: positions.get(c.id)!.y },
    }
  })
  const edges: ElementDefinition[] = lines.value
    .filter((l) => positions.has(l.source) && positions.has(l.target) && l.source !== l.target)
    .map((l) => {
      const routeLine = routeLines.value.get(l.key)
      if (routeLine) {
        // The badge at the middle, the words below it (§11.4).
        const a = positions.get(l.source)!
        const b = positions.get(l.target)!
        const { weights, distances, mid } = routeBend(a, b)
        // Down a column the words sit beside the badge, to its right; elsewhere below it.
        const side = Math.abs(a.x - b.x) < 1 ? 1 : 0
        const words = side ? { x: mid.x + 16, y: mid.y } : { x: mid.x, y: mid.y + ROUTE_WORDS_BELOW }
        return { group: 'edges', data: { id: l.key, source: l.source, target: l.target, label: routeLine.words, line: l.style, sec: 0, role: routeLine.role, side, weights, distances, mx: words.x, my: words.y, alts: [] } }
      }
      const a: Placed = positions.get(l.source)!
      const b: Placed = positions.get(l.target)!
      const { weights, distances, mid, alts } = bend(a, b, flatRun(a, b, laid.value.lanes))
      const sec = security.value && SECURITY_EDGE_TYPES.has(l.type) ? 1 : 0
      return { group: 'edges', data: { id: l.key, source: l.source, target: l.target, label: edgeWord(l.type, l.target), line: l.style, sec, weights, distances, mx: mid.x, my: mid.y, alts } }
    })
  return [...nodes, ...edges]
}

function style(): cytoscape.StylesheetJson {
  const edge = token('--graph-edge')
  const accent = token('--accent')
  const text2 = token('--text-2')
  const text3 = token('--text-3')
  const dim = Number(token('--graph-dim')) || 0.3
  const entry = token('--route-entry')
  const lateral = token('--route-lateral')
  const step = reduced ? 0 : parseFloat(token('--motion-route-step')) || 0
  return [
    {
      selector: 'node',
      style: { width: 'data(w)', height: 'data(h)', shape: 'data(shape)' as never, 'background-opacity': 0, 'border-width': 0, label: '', events: 'no' },
    },
    {
      selector: 'edge',
      style: {
        width: 1.6,
        'line-color': edge,
        'target-arrow-color': edge,
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.9,
        'curve-style': 'unbundled-bezier',
        'edge-distances': 'node-position',
        'control-point-weights': 'data(weights)' as never,
        'control-point-distances': 'data(distances)' as never,
        'line-style': 'data(line)' as never,
        'line-dash-pattern': [6, 4],
        'line-dash-offset': 0,
        // The lit glow: an accent underlay, invisible until an edge is lit.
        'underlay-color': accent,
        'underlay-opacity': 0,
        'underlay-padding': 5,
        'transition-property': 'opacity, line-color, target-arrow-color, width, underlay-opacity',
        'transition-duration': reduced ? 0 : 160,
      } as never,
    },
    { selector: 'edge[line = "dotted"]', style: { 'line-dash-pattern': [1.5, 3] } },
    // A security line (the Security view): heavier and lighter in tone than a connection; hover
    // and lit below still win.
    { selector: 'edge[sec = 1]', style: { width: 2.2, 'line-color': text3, 'target-arrow-color': text3 } },
    { selector: 'edge.hover', style: { 'line-color': text2, 'target-arrow-color': text2 } },
    // Lit (a trace, the selection): accent line with a soft glow.
    {
      selector: 'edge.lit',
      style: { width: 2.4, 'line-color': accent, 'target-arrow-color': accent, 'underlay-opacity': 0.14 } as never,
    },
    { selector: 'edge.dim', style: { opacity: dim } },
    // The Attack Path view (§11.2, owner 2026-11-16: red advancing on grey): a step the player has
    // reached is in its red, told apart by width and arrowhead as well; one not reached yet is the
    // map's own grey line; the current step is heavier with the lit underlay. A step turns red
    // over --motion-route-step. Hover changes nothing on a route.
    { selector: 'edge[role]', style: { 'transition-duration': step } as never },
    { selector: 'edge[role = "entry"]', style: { width: 3.2, 'line-color': entry, 'target-arrow-color': entry, 'arrow-scale': 1.3 } },
    { selector: 'edge[role = "lateral"]', style: { width: 2.4, 'line-color': lateral, 'target-arrow-color': lateral, 'arrow-scale': 0.9 } },
    { selector: 'edge[role].ahead', style: { width: 1.6, 'line-color': edge, 'target-arrow-color': edge, 'arrow-scale': 0.9 } },
    {
      selector: 'edge[role].current',
      style: { 'underlay-opacity': 0.22, 'underlay-padding': 6, 'transition-duration': step } as never,
    },
    { selector: 'edge[role = "entry"].current', style: { width: 4 } },
    { selector: 'edge[role = "lateral"].current', style: { width: 3.2 } },
  ]
}

/** A route line the player has not reached yet. */
function isAhead(key: string): boolean {
  const n = routeLines.value.get(key)?.n
  return props.route != null && n != null && n > props.route.current
}

function paint(): void {
  const c = cy.value
  if (!c) return
  c.batch(() => {
    c.edges().forEach((e: EdgeSingular) => {
      const key = e.id()
      const isLit = lit.value?.lines.has(key) ?? false
      if (routed.value) {
        e.toggleClass('current', isLit)
        e.toggleClass('ahead', isAhead(key))
        return
      }
      e.toggleClass('lit', isLit)
      e.toggleClass('dim', lit.value != null && !isLit)
    })
  })
  placeLabels()
}

/** Which lines show their words (`words`, drawn in the HTML layer). A word never sits under a
 * card: one whose box would touch a card waits, unless hovered or lit, when it is drawn above.
 * Then greedy by priority:
 * the hovered line, then a lit trace, then lines touching the focus, then reading order;
 * a label whose box would overlap one already placed waits until it is hovered or lit. Below
 * LABEL_MIN_ZOOM only hovered and lit lines are labelled. */
function placeLabels(): void {
  const c = cy.value
  if (!c) return
  const z = c.zoom()
  // Every route line keeps its words (at most 12): they are drawn as a lit line's.
  const rank = (e: EdgeSingular): number =>
    routed.value ? 1 : e.hasClass('hover') ? 0 : e.hasClass('lit') ? 1 : e.data('source') === props.focus || e.data('target') === props.focus ? 2 : 3
  const candidates = c
    .edges()
    .toArray()
    .filter((e) => z >= LABEL_MIN_ZOOM || rank(e) <= 1)
    .sort((a, b) => rank(a) - rank(b) || a.data('my') - b.data('my') || a.data('mx') - b.data('mx'))
  const placed: { x1: number; x2: number; y1: number; y2: number }[] = []
  const shown: LineWord[] = []
  const blocks = cards.value.flatMap((card) => {
    const p = laid.value.positions.get(card.id)
    const [w, h] = sizeOf(card)
    return p ? [{ x1: p.x - w / 2, x2: p.x + w / 2, y1: p.y - h / 2, y2: p.y + h / 2 }] : []
  })
  for (const e of candidates) {
    const w = (String(e.data('label')).length * CHAR_PX + 2 * LABEL_PAD + 4) / z
    const h = (LABEL_PX + 2 * LABEL_PAD + 2) / z
    // The middle first, then a quarter of the way from either end.
    // A route line down a column: its words start beside the line (mx is their left edge).
    const first = e.data('side') === 1 ? { x: e.data('mx') + w / 2, y: e.data('my') } : { x: e.data('mx'), y: e.data('my') }
    const spots: { x: number; y: number }[] = [first, ...((e.data('alts') as { x: number; y: number }[] | undefined) ?? [])]
    const r = rank(e)
    const spot = spots.find((at) => {
      const box = { x1: at.x - w / 2, x2: at.x + w / 2, y1: at.y - h / 2, y2: at.y + h / 2 }
      const touches = (p: typeof box) => box.x1 < p.x2 && p.x1 < box.x2 && box.y1 < p.y2 && p.y1 < box.y2
      return !placed.some(touches) && !(r > 1 && blocks.some(touches))
    })
    if (!spot) continue
    placed.push({ x1: spot.x - w / 2, x2: spot.x + w / 2, y1: spot.y - h / 2, y2: spot.y + h / 2 })
    const tone = routed.value ? (e.hasClass('current') ? 'lit' : 'rest') : r === 0 ? 'hover' : r === 1 ? 'lit' : 'rest'
    const ahead = routed.value && isAhead(e.id())
    shown.push({ key: e.id(), text: e.data('label'), x: spot.x, y: spot.y, tone, sec: (routed.value && !ahead) || e.data('sec') === 1, ahead })
  }
  words.value = shown
}

let labelFrame = 0
/** placeLabels() once per frame at most (a wheel zooms in many small steps). */
function scheduleLabels(): void {
  if (labelFrame) return
  labelFrame = window.requestAnimationFrame(() => {
    labelFrame = 0
    placeLabels()
  })
}
onBeforeUnmount(() => window.cancelAnimationFrame(labelFrame))

function rebuild(): void {
  const c = cy.value
  if (!c) return
  c.batch(() => {
    c.elements().remove()
    c.add(elements())
  })
  paint()
}

// A small map fills the canvas (round M, spec §4: capping the fit at 100% left it small in the
// middle of a wide screen).
const MAX_FIT_ZOOM = 1.5
const FIT_PADDING = 56
/** The whole drawing in map coordinates: the cards and lines, and the column names above them,
 * so a fit never cuts any of them. */
function drawingBox(c: Core): { x1: number; y1: number; x2: number; y2: number; w: number; h: number } {
  const b = c.elements().boundingBox()
  const { x1, x2, y2 } = b
  let { y1 } = b
  for (const col of columnNames.value) y1 = Math.min(y1, col.top - 8)
  return { x1, y1, x2, y2, w: x2 - x1, h: y2 - y1 }
}

/** Fits these elements (the whole drawing by default), never above MAX_FIT_ZOOM: the zoom is worked
 * out first, so an animation ends where it should. */
function fit(eles?: cytoscape.CollectionArgument, animate = false): void {
  const c = cy.value
  if (!c || c.elements().length === 0) return
  const box = eles ? c.collection().union(eles).boundingBox() : drawingBox(c)
  const level = Math.max(c.minZoom(), Math.min(MAX_FIT_ZOOM, (c.width() - 2 * FIT_PADDING) / Math.max(box.w, 1), (c.height() - 2 * FIT_PADDING) / Math.max(box.h, 1)))
  const viewport = { zoom: level, pan: { x: c.width() / 2 - (box.x1 + box.w / 2) * level, y: c.height() / 2 - (box.y1 + box.h / 2) * level } }
  if (animate && !reduced) c.animate(viewport, { duration: 200, easing: 'ease-out' })
  else c.viewport(viewport)
}

// The opening view reads (spec frontend/d37cd13b, B): everything when it fits at this zoom or
// more, else this zoom centred on the focus, with the overview for the rest.
const OPEN_ZOOM = 0.8
/** The first view of a graph: everything fitted if the cards stay readable, else the focus at a
 * readable zoom. */
function firstView(): void {
  const c = cy.value
  if (!c || c.elements().length === 0) return
  // A view switch on the same focus keeps the camera: the cards are where they were.
  if (props.initialViewport) {
    const { zoom: z, pan: p, anchor } = props.initialViewport
    const now = anchor ? laid.value.positions.get(anchor.id) : undefined
    // The focus card stays where it was on screen, even if the other view added a row above it.
    const shift = now && anchor ? { x: (anchor.x - now.x) * z, y: (anchor.y - now.y) * z } : { x: 0, y: 0 }
    c.viewport({ zoom: z, pan: { x: p.x + shift.x, y: p.y + shift.y } })
    return
  }
  // A route opens whole (§11.4): at most 150 %, and the map's minimum zoom, below which it pans.
  if (routed.value) {
    fit()
    return
  }
  const box = drawingBox(c)
  const level = Math.min(MAX_FIT_ZOOM, (c.width() - 2 * FIT_PADDING) / Math.max(box.w, 1), (c.height() - 2 * FIT_PADDING) / Math.max(box.h, 1))
  const focusEl = props.focus ? c.getElementById(props.focus) : null
  if (level >= OPEN_ZOOM || !focusEl || focusEl.empty()) {
    fit()
    return
  }
  // Centred on the focus, but never past the drawing's edge: no empty band where the drawing
  // could be (map_idea.txt: "a great deal of empty space").
  const p = focusEl.position()
  const z = OPEN_ZOOM
  const clamp = (pan: number, lo: number, hi: number, size: number): number => {
    const min = size - FIT_PADDING - hi * z // the far edge reaches the canvas's far side
    const max = FIT_PADDING - lo * z // the near edge reaches the canvas's near side
    return min > max ? (min + max) / 2 : Math.min(max, Math.max(min, pan))
  }
  c.viewport({
    zoom: z,
    pan: {
      x: clamp(c.width() / 2 - p.x * z, box.x1, box.x2, c.width()),
      y: clamp(c.height() / 2 - p.y * z, box.y1, box.y2, c.height()),
    },
  })
}

/** The drawn elements with these ids (an id no longer drawn is skipped). */
function collect(ids: string[]): cytoscape.CollectionReturnValue | null {
  const c = cy.value
  if (!c) return null
  let found = c.collection()
  for (const id of ids) {
    const el = c.getElementById(id)
    if (el.nonempty()) found = found.union(el)
  }
  return found
}

function zoomBy(factor: number): void {
  const c = cy.value
  if (!c) return
  const level = Math.min(c.maxZoom(), Math.max(c.minZoom(), c.zoom() * factor))
  c.zoom({ level, renderedPosition: { x: c.width() / 2, y: c.height() / 2 } })
}
/** The zoom readout's click: 100 % about the canvas's centre. */
function zoomActual(): void {
  const c = cy.value
  if (c) c.zoom({ level: 1, renderedPosition: { x: c.width() / 2, y: c.height() / 2 } })
}
const zoomPercent = computed(() => `${Math.round(zoom.value * 100)} %`)

/** Brings a card to the canvas's centre when it lies outside the middle 60 % (spec §4). The
 * zoom never changes. */
function centreIfAside(id: string): void {
  const c = cy.value
  const el = c?.getElementById(id)
  if (!c || !el || el.empty()) return
  const p = el.renderedPosition()
  const mx = c.width() * 0.2
  const my = c.height() * 0.2
  if (p.x >= mx && p.x <= c.width() - mx && p.y >= my && p.y <= c.height() - my) return
  const viewport = { zoom: c.zoom(), pan: { x: c.width() / 2 - el.position('x') * c.zoom(), y: c.height() / 2 - el.position('y') * c.zoom() } }
  if (reduced) c.viewport(viewport)
  else c.animate(viewport, { duration: 300, easing: 'ease-out' })
}

/** The camera, for MapView to carry across a view switch. */
function viewport(): Viewport | null {
  const c = cy.value
  if (!c) return null
  const at = props.focus ? laid.value.positions.get(props.focus) : undefined
  return { zoom: c.zoom(), pan: { ...c.pan() }, anchor: at && props.focus ? { id: props.focus, x: at.x, y: at.y } : null }
}

function track(instance: Core): void {
  pan.value = { ...instance.pan() }
  if (instance.zoom() !== zoom.value) scheduleLabels()
  zoom.value = instance.zoom()
  size.value = { w: instance.width(), h: instance.height() }
}

onMounted(() => {
  if (!container.value) return
  const instance = cytoscape({
    container: container.value,
    elements: [],
    style: style(),
    layout: { name: 'preset' },
    minZoom: 0.3,
    maxZoom: 2,
    boxSelectionEnabled: false,
    autoungrabify: true,
    autounselectify: true,
  })
  instance.on('viewport resize', () => track(instance))
  instance.on('tap', (event) => {
    if (event.target === instance) emit('select', null)
    else if (event.target.isEdge()) {
      const key = event.target.id() as string
      if (!key.startsWith('group:')) emit('select', { kind: 'edge', key })
    }
  })
  instance.on('mouseover', 'edge', (event) => {
    event.target.addClass('hover')
    placeLabels()
  })
  instance.on('mouseout', 'edge', (event) => {
    event.target.removeClass('hover')
    placeLabels()
  })
  cy.value = instance
  known = new Set(cards.value.map((c) => c.id))
  measureAspect()
  rebuild()
  firstView()
  track(instance)
})
// The canvas narrows when the panel docks (and on window resizes): Cytoscape is told, and the
// selection comes back to the middle if the new edge pushed it aside (the same rule as a click).
let resizeObserver: ResizeObserver | null = null
onMounted(() => {
  if (!region.value || typeof ResizeObserver === 'undefined') return
  // Only a real change of size moves the camera: the observer also fires once when it starts,
  // and the camera carried across a view switch must stay where it was put.
  let seen = { w: region.value.clientWidth, h: region.value.clientHeight }
  resizeObserver = new ResizeObserver(() => {
    const c = cy.value
    const el = region.value
    if (!c || !el) return
    c.resize()
    track(c)
    const now = { w: el.clientWidth, h: el.clientHeight }
    if (now.w === seen.w && now.h === seen.h) return
    seen = now
    if (selectedNode.value) centreIfAside(selectedNode.value)
  })
  resizeObserver.observe(region.value)
})
onBeforeUnmount(() => {
  resizeObserver?.disconnect()
  cy.value?.destroy()
})

// A new response: redraw, and bring what it added into view.
watch([cards, lines], () => {
  const before = known
  known = new Set(cards.value.map((c) => c.id))
  // A new neighbourhood is laid out for the canvas as it is now; an Expand keeps the shape.
  if (before.size === 0) measureAspect()
  rebuild()
  const added = [...known].filter((id) => !before.has(id))
  const c = cy.value
  if (!c || added.length === 0) return
  if (before.size === 0) {
    firstView()
    return
  }
  const anchor = selectedNode.value ? [selectedNode.value] : []
  const eles = collect([...anchor, ...added])
  if (!eles) return
  const extent = c.extent()
  const box = eles.boundingBox()
  const outside = box.x1 < extent.x1 || box.x2 > extent.x2 || box.y1 < extent.y1 || box.y2 > extent.y2
  if (outside) fit(eles, true)
})
watch(lit, paint)
// The Attack Path view: a step change brings its line into view when either end is outside it,
// over --motion-route-pan (none under reduced motion). The zoom never changes.
watch(
  () => props.route?.current,
  (n) => {
    const c = cy.value
    if (n == null || !c || !lit.value) return
    const ends = collect([...lit.value.nodes])
    if (!ends || ends.empty()) return
    const extent = c.extent()
    const box = ends.boundingBox()
    if (box.x1 >= extent.x1 && box.x2 <= extent.x2 && box.y1 >= extent.y1 && box.y2 <= extent.y2) return
    const viewport = { zoom: c.zoom(), pan: { x: c.width() / 2 - (box.x1 + box.w / 2) * c.zoom(), y: c.height() / 2 - (box.y1 + box.h / 2) * c.zoom() } }
    const duration = reduced ? 0 : parseFloat(token('--motion-route-pan')) || 0
    if (duration) c.animate(viewport, { duration, easing: 'ease-out' })
    else c.viewport(viewport)
  },
)
// A step's number at each route line's middle, and the tab over a card a foothold or a login
// stands on (§4.3): HTML, with the cards.
const badges = computed(() => {
  if (!props.route) return []
  const positions = laid.value.positions
  return props.route.drawing.lines.flatMap((l) => {
    const a = positions.get(l.source)
    const b = positions.get(l.target)
    if (!a || !b) return []
    const { mid } = routeBend(a, b)
    return [{ n: l.n, x: mid.x, y: mid.y, current: l.n === props.route!.current }]
  })
})
const footTabs = computed(() => {
  if (!props.route) return []
  return props.route.drawing.selfSteps.flatMap((x) => {
    const p = laid.value.positions.get(x.on)
    const card = byId.value.get(x.on)
    return p && card ? [{ n: x.n, text: x.tab, x: p.x, y: p.y - card.h / 2 - 6, current: x.n === props.route!.current }] : []
  })
})
// A card chosen at the edge (a click, the keyboard, the List view) comes to the centre.
watch(selectedNode, (id) => {
  if (id) void nextTick(() => centreIfAside(id))
})
// The canvas reads the tokens once: a theme change restyles it with the new values.
watch(resolvedTheme, () => {
  void nextTick(() => {
    cy.value?.style(style())
    paint()
  })
})
// ---- The HTML layer, the dot grid and the column names.
// --word-scale undoes the layer's zoom: a line's words keep one size on screen.
const worldStyle = computed(() => ({ transform: `translate(${pan.value.x}px, ${pan.value.y}px) scale(${zoom.value})`, '--word-scale': 1 / zoom.value }))
const far = computed(() => zoom.value < 0.55)
const GRID = 22
// The dot grid moves and scales with the map.
const regionStyle = computed(() => ({ backgroundSize: `${GRID * zoom.value}px ${GRID * zoom.value}px`, backgroundPosition: `${pan.value.x}px ${pan.value.y}px` }))
function cardStyle(card: Card): Record<string, string> {
  const p = laid.value.positions.get(card.id)
  if (!p) return { display: 'none' }
  const [w, h] = sizeOf(card)
  return { left: `${p.x - w / 2}px`, top: `${p.y - h / 2}px`, width: `${w}px`, height: `${h}px` }
}
// One row of column names, above the highest card.
const columnNames = computed(() => {
  let top = Infinity
  for (const p of laid.value.positions.values()) top = Math.min(top, p.y - NODE_HEIGHT / 2)
  if (!Number.isFinite(top)) return []
  return laid.value.lanes.map((l) => ({ lane: l.lane, label: l.label, left: l.x + l.width / 2, top: top - LANE_NAME_RISE + NODE_HEIGHT / 2 }))
})

// Cards sit above the canvas: a wheel over one still zooms the map.
function onWheel(event: WheelEvent): void {
  const c = cy.value
  if (!c || !container.value) return
  event.preventDefault()
  const box = container.value.getBoundingClientRect()
  const level = Math.min(c.maxZoom(), Math.max(c.minZoom(), c.zoom() * Math.pow(1.0015, -event.deltaY)))
  c.zoom({ level, renderedPosition: { x: event.clientX - box.left, y: event.clientY - box.top } })
}

/** Whether Expand can add this card's own hop: a resource of this connection not yet read. */
function expandable(card: Card): boolean {
  return !!card.node && !card.node.expanded && !card.node.boundary && card.kind !== 'external' && card.kind !== 'any'
}
/** E on the keyboard expands, as the panel's button does. No double click: the first click
 * docks the panel, which narrows the canvas, so the second can land on the panel. */
function expandCard(card: Card): void {
  if (expandable(card)) emit('expand', card.id)
}

function clickCard(card: Card): void {
  hovered.value = null
  active.value = card.id
  emit('select', card.kind === 'group' && card.group ? { kind: 'group', id: card.group.id } : { kind: 'node', id: card.id })
}

// ---- Hover: traces the card's lines at once; a tooltip after 300 ms.
const TIP_WIDTH = 320 // .tip's max-width
const tip = ref<{ card: Card; x: number; y: number } | null>(null)
let tipTimer: number | undefined
function hover(card: Card, event: MouseEvent): void {
  hovered.value = card.id
  window.clearTimeout(tipTimer)
  const box = region.value?.getBoundingClientRect()
  const target = (event.currentTarget as HTMLElement).getBoundingClientRect()
  tipTimer = window.setTimeout(() => {
    // Kept inside the canvas: a docked panel narrows it, and the Security view's tooltip is wider.
    if (box) tip.value = { card, x: Math.max(8, Math.min(target.left - box.left, box.width - TIP_WIDTH - 8)), y: target.bottom - box.top + 6 }
  }, 300)
}
function unhover(): void {
  hovered.value = null
  window.clearTimeout(tipTimer)
  tip.value = null
}
onBeforeUnmount(() => window.clearTimeout(tipTimer))

// ---- Keyboard.
const active = ref<string | null>(null)
const focused = ref(false)
watch(
  () => props.selection,
  (sel) => {
    if (sel?.kind === 'node') active.value = sel.id
    else if (sel?.kind === 'group') active.value = `group:${sel.id}`
  },
)
const KEYS: Record<string, Move> = { ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right' }
function onKey(event: KeyboardEvent): void {
  // The legend and zoom buttons inside the region handle their own keys.
  if (event.target !== region.value) return
  const move = KEYS[event.key]
  if (move) {
    event.preventDefault()
    active.value = moveSelection(laid.value.positions, active.value, move, props.focus)
    const c = cy.value
    const el = active.value ? c?.getElementById(active.value) : null
    if (c && el && el.length) {
      const p = el.renderedPosition()
      if (p.x < 0 || p.y < 0 || p.x > c.width() || p.y > c.height()) c.center(el)
    }
    return
  }
  const card = active.value ? byId.value.get(active.value) : undefined
  if (event.key === 'Enter' && card) {
    event.preventDefault()
    clickCard(card)
  } else if ((event.key === 'e' || event.key === 'E') && card) {
    expandCard(card)
  } else if ((event.key === 'c' || event.key === 'C') && card && props.collapsible?.has(card.id)) {
    emit('collapse', card.id)
  } else if ((event.key === 'f' || event.key === 'F') && card?.node && card.kind === 'resource') {
    emit('focusHere', card.id)
  } else if (event.key === 'Escape') {
    active.value = null
    emit('select', null)
  }
}
const announcement = computed(() => {
  const card = active.value ? byId.value.get(active.value) : undefined
  if (!card || !focused.value) return ''
  const lane = laid.value.positions.get(card.id)?.lane
  const where = lane ? `, ${laneLabel.value.get(lane)} column` : ''
  const facts = card.kind === 'group' ? [] : card.facts.map((f) => `, ${f}`)
  return `${card.name}, ${card.typeLabel}${where}${card.kind === 'group' ? `, ${card.group?.count} resources` : ''}${facts.join('')}.`
})
const regionLabelText = computed(() =>
  props.route
    ? `Map, Attack Path view: ${props.route.title}. The step list beside the map holds the same steps.`
    : `Map, ${security.value ? 'Security' : 'Infrastructure'} view, ${props.graph.nodes.size} resources. The List view shows the same resources as a table.`,
)

// ---- Legend: a popover from its button, closed by default and remembered per browser.
const LEGEND_KEY = 'argus.map.legend'
function readLegend(): boolean {
  try {
    return window.localStorage.getItem(LEGEND_KEY) === 'open'
  } catch {
    return false
  }
}
const legendOpen = ref(readLegend())
watch(legendOpen, (open) => {
  try {
    window.localStorage.setItem(LEGEND_KEY, open ? 'open' : 'closed')
  } catch {
    // Storage blocked: the legend simply starts closed next time.
  }
})
const controlsRef = ref<HTMLElement | null>(null)
function closeLegendOutside(event: PointerEvent): void {
  if (legendOpen.value && controlsRef.value && !controlsRef.value.contains(event.target as Node)) legendOpen.value = false
}
onMounted(() => document.addEventListener('pointerdown', closeLegendOutside))
onBeforeUnmount(() => document.removeEventListener('pointerdown', closeLegendOutside))

// ---- Overview: every node as a block, every line straight, and the visible part of the map.
const OV = { w: 210, h: 120, pad: 12, top: 20 }
const overview = computed(() => {
  const pos = laid.value.positions
  let x1 = Infinity
  let y1 = Infinity
  let x2 = -Infinity
  let y2 = -Infinity
  for (const card of cards.value) {
    const p = pos.get(card.id)
    if (!p) continue
    const [w, h] = sizeOf(card)
    x1 = Math.min(x1, p.x - w / 2)
    x2 = Math.max(x2, p.x + w / 2)
    y1 = Math.min(y1, p.y - h / 2)
    y2 = Math.max(y2, p.y + h / 2)
  }
  if (!Number.isFinite(x1)) return null
  const room = { w: OV.w - 2 * OV.pad, h: OV.h - OV.top - OV.pad }
  const scale = Math.min(room.w / Math.max(x2 - x1, 1), room.h / Math.max(y2 - y1, 1))
  const ox = OV.pad + (room.w - (x2 - x1) * scale) / 2 - x1 * scale
  const oy = OV.top + (room.h - (y2 - y1) * scale) / 2 - y1 * scale
  const blocks = cards.value.flatMap((card) => {
    const p = pos.get(card.id)
    const [w, h] = sizeOf(card)
    return p ? [{ id: card.id, x: ox + (p.x - w / 2) * scale, y: oy + (p.y - h / 2) * scale, w: w * scale, h: h * scale }] : []
  })
  const segments = lines.value.flatMap((l) => {
    const a = pos.get(l.source)
    const b = pos.get(l.target)
    return a && b ? [{ key: l.key, x1: ox + a.x * scale, y1: oy + a.y * scale, x2: ox + b.x * scale, y2: oy + b.y * scale }] : []
  })
  return { scale, ox, oy, blocks, segments }
})
const viewRect = computed(() => {
  const o = overview.value
  if (!o || !size.value.w) return null
  const z = zoom.value
  // Clamped to the overview, so a view wider than the map still shows its edges.
  const x1 = Math.max(1, o.ox + (-pan.value.x / z) * o.scale)
  const y1 = Math.max(OV.top - 2, o.oy + (-pan.value.y / z) * o.scale) // under the caption
  const x2 = Math.min(OV.w - 1, o.ox + ((size.value.w - pan.value.x) / z) * o.scale)
  const y2 = Math.min(OV.h - 1, o.oy + ((size.value.h - pan.value.y) / z) * o.scale)
  return x2 > x1 && y2 > y1 ? { x: x1, y: y1, w: x2 - x1, h: y2 - y1 } : null
})
let dragging = false
/** Centres the map on the overview's point under the pointer. */
function overviewTo(event: PointerEvent): void {
  const c = cy.value
  const o = overview.value
  if (!c || !o) return
  const box = (event.currentTarget as SVGElement).getBoundingClientRect()
  const mx = (event.clientX - box.left - o.ox) / o.scale
  const my = (event.clientY - box.top - o.oy) / o.scale
  c.pan({ x: c.width() / 2 - mx * c.zoom(), y: c.height() / 2 - my * c.zoom() })
}
function overviewDown(event: PointerEvent): void {
  dragging = true
  ;(event.currentTarget as SVGElement).setPointerCapture?.(event.pointerId)
  overviewTo(event)
}
function overviewMove(event: PointerEvent): void {
  if (dragging) overviewTo(event)
}
function overviewUp(): void {
  dragging = false
}

defineExpose({ fit, viewport })
</script>

<template>
  <div
    ref="region"
    class="region"
    :style="regionStyle"
    tabindex="0"
    role="application"
    aria-roledescription="map"
    :aria-label="regionLabelText"
    @keydown="onKey"
    @focus="focused = true"
    @blur="focused = false"
  >
    <!-- Cytoscape adds an inline <style> unless an element with this id exists; the CSP
         (style-src 'self') would refuse it. The container's position is set below instead. -->
    <span id="__________cytoscape_stylesheet" hidden></span>
    <div ref="container" class="cy"></div>
    <div class="world" :class="{ far }" :style="worldStyle" aria-hidden="true" @wheel="onWheel">
      <span v-for="col in columnNames" :key="col.lane" class="eyebrow col-name" :style="{ left: `${col.left}px`, top: `${col.top}px` }">{{ col.label }}</span>
      <span v-for="w in words" :key="w.key" class="line-word" :class="[w.tone, { sec: w.sec, ahead: w.ahead }]" :style="{ left: `${w.x}px`, top: `${w.y}px` }">{{ w.text }}</span>
      <span v-for="b in badges" :key="`b${b.n}`" class="step-badge mono" :class="{ current: b.current }" :style="{ left: `${b.x}px`, top: `${b.y}px` }">{{ b.n }}</span>
      <span v-for="t in footTabs" :key="`t${t.n}`" class="foot-tab" :class="{ current: t.current }" :style="{ left: `${t.x}px`, top: `${t.y}px` }"><span class="mono">{{ t.n }}</span> {{ t.text }}</span>
      <div
        v-for="card in cards"
        :key="card.id"
        class="node"
        :class="[
          `kind-${card.kind}`,
          frameOf(card) ? `frame-${frameOf(card)}` : '',
          {
            focus: card.id === focus,
            selected: card.id === selectedNode || (routed && !!lit?.nodes.has(card.id)),
            active: focused && card.id === active,
            faded: dimmed(card.id),
            boundary: card.node?.boundary,
          },
        ]"
        :style="cardStyle(card)"
        @click="clickCard(card)"
        @mouseenter="hover(card, $event)"
        @mouseleave="unhover"
      >
        <template v-if="card.kind === 'internet'">
          <span class="ring"></span>
          <span class="ring late"></span>
          <span class="circle"><AppIcon name="globe" :size="30" :stroke="1.5" /></span>
          <span class="under">Internet</span>
        </template>
        <template v-else-if="card.kind === 'admin'">
          <span class="diamond"></span>
          <span class="under">{{ card.name }}</span>
        </template>
        <template v-else>
          <span v-if="card.kind === 'group'" class="back"></span>
          <span v-if="frameOf(card)" class="frame-word">{{ SEVERITY_LABEL[frameOf(card)!] }}</span>
          <span class="face">
            <span class="tile"><AppIcon :name="card.icon" :size="20" :stroke="1.6" /></span>
            <span class="lines">
              <span class="line1" :class="{ mono: card.kind === 'external' }">
                <template v-if="card.kind === 'group'"><span class="mono">{{ card.group?.count }}</span> {{ card.name }}</template>
                <template v-else>{{ card.name }}</template>
              </span>
              <span class="line2-row">
                <span class="line2 mono">{{ card.typeLabel }}</span>
                <span v-if="card.marks" class="marks">
                  <span v-if="card.marks.internet" class="mark mark-internet" title="Reachable from the internet"><AppIcon name="globe" :size="14" :stroke="1.8" /></span>
                  <span v-if="card.marks.vulnerable" class="mark mark-vulnerable" title="Open vulnerabilities"><AppIcon name="bug" :size="14" :stroke="1.8" /></span>
                  <span v-if="card.marks.exploit" class="mark mark-exploit exploit" title="A public exploit"><AppIcon name="warning" :size="14" :stroke="1.8" /></span>
                </span>
              </span>
            </span>
            <CountPill v-if="card.pill" class="card-pill" :count="card.pill.count" :severity="card.pill.severity" />
          </span>
        </template>
      </div>
    </div>

    <div v-if="tip" class="tip" role="tooltip" :style="{ left: `${tip.x}px`, top: `${tip.y}px` }">
      <strong>{{ tip.card.name }}</strong>
      <span class="mono">{{ tip.card.type ?? tip.card.typeLabel }}</span>
      <span v-if="tip.card.node?.region || tip.card.node?.connection_id">
        {{ tip.card.node?.region ? regionLabel(tip.card.node.region) : '' }}{{ tip.card.node?.connection_id ? ` · ${connectionName(tip.card.node.connection_id)}` : '' }}
      </span>
      <span v-for="f in tip.card.facts" :key="f" class="fact">{{ f }}</span>
    </div>

    <p class="sr-only" aria-live="polite">{{ announcement }}</p>

    <!-- The page's pill (the first-use hint), top left. -->
    <div class="overlay"><slot name="overlay" /></div>

    <div ref="controlsRef" class="controls" @keydown.esc.stop="legendOpen = false">
      <dl v-show="legendOpen" id="map-legend" class="legend-body">
        <template v-if="routed">
          <div class="wide"><dt><svg width="28" height="10" aria-hidden="true"><line x1="0" y1="5" x2="22" y2="5" class="l entry" /><path d="M21 1l7 4-7 4z" class="arrow entry" /></svg></dt><dd>Internet entry: the way in from outside</dd></div>
          <div class="wide"><dt><svg width="28" height="10" aria-hidden="true"><line x1="0" y1="5" x2="23" y2="5" class="l lateral" /><path d="M23 2l5 3-5 3z" class="arrow lateral" /></svg></dt><dd>Lateral move: resource to resource, account to account</dd></div>
          <div class="wide"><dt><span class="step-badge mono legend-badge current">3</span></dt><dd>The current step: its line lit, both cards ringed</dd></div>
          <div class="wide"><dt><svg width="28" height="6" aria-hidden="true"><line x1="0" y1="3" x2="28" y2="3" class="l solid" /></svg></dt><dd>A step not reached yet: grey until the player gets there</dd></div>
          <div class="wide"><dd>Dashed: found by CloudFox only. Dotted: added by hand.</dd></div>
        </template>
        <template v-else>
          <div><dt><svg width="28" height="6" aria-hidden="true"><line x1="0" y1="3" x2="28" y2="3" class="l solid" /></svg></dt><dd>Argus rule</dd></div>
          <div><dt><svg width="28" height="6" aria-hidden="true"><line x1="0" y1="3" x2="28" y2="3" class="l dashed" /></svg></dt><dd>CloudFox only</dd></div>
          <div><dt><span class="sw node-sw"></span></dt><dd>Resource</dd></div>
          <div><dt><span class="sw group-sw"></span></dt><dd>Group of resources</dd></div>
          <div><dt><span class="sw ext-sw"></span></dt><dd>Not in the inventory</dd></div>
          <div><dt><span class="sw boundary-sw"></span></dt><dd>Other connection or account</dd></div>
        </template>
        <template v-if="security">
          <div class="wide"><dt><span class="sw frame-sw"></span></dt><dd>A Critical or High misconfiguration: the border in its colour, its word on the border</dd></div>
          <div v-if="!routed" class="wide"><dt><svg width="28" height="6" aria-hidden="true"><line x1="0" y1="3" x2="28" y2="3" class="l sec" /></svg></dt><dd>Security line: what an identity can do, or the internet reaching a resource</dd></div>
          <div class="wide"><dt><CountPill count="3" severity="high" /></dt><dd>Open misconfigurations, in the worst severity's colour</dd></div>
          <div class="wide"><dt><AppIcon name="globe" :size="14" :stroke="1.8" /></dt><dd>Reachable from the internet (Argus's rules confirm it)</dd></div>
          <div><dt><AppIcon name="bug" :size="14" :stroke="1.8" /></dt><dd>Open vulnerabilities</dd></div>
          <div><dt><AppIcon name="warning" :size="14" :stroke="1.8" class="exploit" /></dt><dd>A public exploit</dd></div>
        </template>
        <div class="wide"><dt><span class="sw-tile"><AppIcon name="server" :size="12" /></span></dt><dd>Icon: the type of resource</dd></div>
        <div v-if="!routed" class="wide"><dd>Data access is what a role's policies allow, not observed traffic.</dd></div>
        <div v-if="security" class="wide"><dd>A line from the internet that CloudFox found is CloudFox's claim; the globe is Argus's confirmed verdict.</dd></div>
        <div v-if="routed" class="wide"><dd>Every line's words say how sure Argus is of it; the step list has each step's level.</dd></div>
      </dl>
      <div class="buttons">
        <button type="button" class="btn btn-secondary btn-sm legend-btn" :aria-expanded="legendOpen" aria-controls="map-legend" @click.stop="legendOpen = !legendOpen">
          <AppIcon name="layers" :size="14" />Legend
        </button>
        <button type="button" class="btn btn-secondary icon-only" aria-label="Zoom in" title="Zoom in" @click.stop="zoomBy(1.25)"><AppIcon name="plus" :size="16" /></button>
        <button type="button" class="btn btn-secondary icon-only" aria-label="Zoom out" title="Zoom out" @click.stop="zoomBy(0.8)"><AppIcon name="minus" :size="16" /></button>
        <button type="button" class="btn btn-secondary icon-only" aria-label="Fit" title="Fit" @click.stop="fit()"><AppIcon name="fit" :size="16" /></button>
        <button type="button" class="btn btn-secondary zoom-readout mono" :aria-label="`Zoom ${zoomPercent}, set to 100 %`" title="Set to 100 %" @click.stop="zoomActual">{{ zoomPercent }}</button>
      </div>
    </div>

    <div v-if="overview" class="overview" aria-hidden="true">
      <span class="eyebrow ov-cap">Overview</span>
      <svg :width="OV.w" :height="OV.h" @pointerdown="overviewDown" @pointermove="overviewMove" @pointerup="overviewUp" @pointercancel="overviewUp">
        <line v-for="seg in overview.segments" :key="seg.key" :x1="seg.x1" :y1="seg.y1" :x2="seg.x2" :y2="seg.y2" class="ov-line" />
        <rect v-for="b in overview.blocks" :key="b.id" :x="b.x" :y="b.y" :width="b.w" :height="b.h" rx="2" class="ov-node" />
        <rect v-if="viewRect" :x="viewRect.x" :y="viewRect.y" :width="viewRect.w" :height="viewRect.h" rx="3" class="ov-view" />
      </svg>
    </div>
  </div>
</template>

<style scoped>
.region {
  position: relative;
  flex: 1;
  min-height: 600px;
  overflow: hidden;
  /* A dot grid; its size and position follow the map (regionStyle). */
  background-color: var(--graph-canvas);
  background-image: radial-gradient(circle, var(--graph-dot) 1px, transparent 1.2px);
  border-radius: 0 0 var(--r-card) var(--r-card);
}

.region:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}

.cy,
.world {
  position: absolute;
  inset: 0;
}

.world {
  transform-origin: 0 0;
  pointer-events: none;
}

.col-name {
  position: absolute;
  transform: translateX(-50%);
  white-space: nowrap;
  letter-spacing: 0.12em;
  color: var(--text-3);
}

.line-word {
  position: absolute;
  z-index: 1;
  transform: translate(-50%, -50%) scale(var(--word-scale));
  padding: 2px 4px;
  border-radius: 4px;
  background: var(--graph-canvas);
  font: 500 11px/1.2 var(--font-sans);
  white-space: nowrap;
  color: var(--text-2);
}

.line-word.sec {
  font-weight: 600;
}

.line-word.hover {
  color: var(--text);
}

/* Lit: the strongest text colour (accent text would fail contrast). */
.line-word.lit {
  color: var(--text-strong);
}

/* The Attack Path view (W6 §4.3, §11.2): a step's number at its line's middle, one size on
   screen; the current one's border is the accent. Order never rests on colour. */
.step-badge {
  position: absolute;
  z-index: 2;
  display: inline-grid;
  place-items: center;
  width: 20px;
  height: 20px;
  transform: translate(-50%, -50%) scale(var(--word-scale));
  border: 1px solid var(--graph-edge);
  border-radius: 50%;
  background: var(--graph-node);
  color: var(--text);
  font-size: 11px;
  transition: border-color var(--ease), color var(--ease);
}

.step-badge.current {
  border: 2px solid var(--accent);
  color: var(--text-strong);
  font-weight: 600;
}

.legend-badge {
  position: static;
  transform: none;
}

/* A foothold or a login: an assumption, not a line. A dashed tab over the card it stands on. */
.foot-tab {
  position: absolute;
  z-index: 2;
  height: 20px;
  padding: 0 var(--s-8);
  transform: translate(-50%, -100%) scale(var(--word-scale));
  transform-origin: 50% 100%;
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
  border: 1px dashed var(--text-3);
  border-radius: var(--r-tile) var(--r-tile) 0 0;
  background: var(--graph-node);
  color: var(--text-2);
  font: 500 11px/1 var(--font-sans);
  white-space: nowrap;
}

.foot-tab.current {
  border: 2px solid var(--accent);
  color: var(--text-strong);
}

.node {
  position: absolute;
  pointer-events: auto;
  cursor: pointer;
  animation: appear 160ms ease-out;
}

@keyframes appear {
  from {
    opacity: 0;
  }
}

.face,
.back {
  position: absolute;
  inset: 0;
  border-radius: var(--r-tile);
}

/* Round M's card (spec §5): a rectangle with a square icon tile, then the name and the type. */
.face {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 12px;
  background: var(--graph-node);
  border: 1px solid var(--border-strong);
  transition:
    border-color 160ms,
    box-shadow 160ms;
}

.tile {
  flex: none;
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: var(--r-control);
  /* One colour for every type: the glyph and the second line tell types apart. */
  color: var(--text-2);
  background: var(--tile);
  border: 1px solid var(--tile-border);
  transition: opacity 160ms;
}

/* Security view: a Critical or High worst misconfiguration frames the card, its word on the
   frame so the colour is never the only cue. */
.node.frame-critical .face {
  border: 1.5px solid var(--sev-critical);
}

.node.frame-high .face {
  border: 1.5px solid var(--sev-high);
}

.frame-word {
  position: absolute;
  z-index: 1;
  top: -9px;
  right: 12px;
  padding: 0 5px;
  font-size: 10px;
  font-weight: 700;
  line-height: 16px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  background: var(--graph-node);
  border-radius: var(--r-chip);
}

.frame-critical .frame-word {
  color: var(--sev-critical-text);
  border: 1px solid var(--sev-critical);
}

.frame-high .frame-word {
  color: var(--sev-high-text);
  border: 1px solid var(--sev-high);
}

.world.far .frame-word {
  visibility: hidden;
}

.lines {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1;
  line-height: 1.25;
}

.line1 {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  transition: color 160ms;
}

.line1.mono {
  font-size: 12px;
  font-weight: 500;
}

.line2 {
  font-size: 11px;
  color: var(--text-3);
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}

/* Line 2 and the Security view's marks after it: the type gives way first. */
.line2-row {
  display: flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
}

.line2-row .line2 {
  min-width: 0;
}

.marks {
  flex: none;
  display: inline-flex;
  gap: 4px;
  color: var(--text-2);
}

.mark {
  display: inline-flex;
}

.marks .exploit,
.legend-body .exploit {
  color: var(--text);
}

/* Card B's count pill (CountPill.vue): 8 px from the lines, at the face's padding. */
.card-pill {
  margin-left: -2px;
}

/* Not on the trace: muted, not faded, so its text keeps the contrast floor (WCAG AA). */
.node.faded .face {
  border-color: var(--border);
}

.node.faded .line1,
.node.faded .under {
  color: var(--text-2);
}

.node.faded .tile,
.node.faded .back,
.node.faded .ring,
.node.faded .card-pill,
.node.faded .marks {
  opacity: var(--graph-dim);
}

.kind-external .face,
.kind-any .face {
  background: transparent;
  border: 1px dashed var(--muted);
}

/* Another connection's or account's resource: drawn, never expanded. */
.node.boundary .face {
  background: var(--graph-lane);
  border: 1.5px dotted var(--text-3);
}

.kind-group .back {
  transform: translate(4px, 4px);
  background: var(--graph-lane);
  border: 1px solid var(--border-strong);
}

.kind-group .face {
  background: var(--graph-lane);
}

/* The internet: a disc with two rings rippling out of it. */
.circle {
  position: absolute;
  inset: 2px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  border: 1px solid var(--border-control);
  background: radial-gradient(circle at 35% 30%, var(--surface-raised), var(--surface-sunken));
  color: var(--text);
  transition: border-color 160ms;
}

.ring {
  position: absolute;
  inset: 8px;
  border-radius: 50%;
  border: 1px solid var(--graph-ring);
  animation: ripple 2.8s ease-out infinite;
}

.ring.late {
  animation-delay: 1.4s;
}

@keyframes ripple {
  from {
    transform: scale(1);
    opacity: 0.7;
  }

  to {
    transform: scale(1.9);
    opacity: 0;
  }
}

.diamond {
  position: absolute;
  inset: 7px;
  transform: rotate(45deg);
  border: 1.5px solid var(--text-2);
  background: var(--graph-node);
}

.under {
  position: absolute;
  top: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%);
  white-space: nowrap;
  font-size: 11.5px;
  color: var(--text-2);
}

.node:hover .face {
  border-color: var(--border-control);
}

.node:hover .circle,
.node:hover .diamond {
  border-color: var(--text);
}

.kind-external:hover .face {
  border-color: var(--text-2);
}

.node.focus .face {
  border: 2px solid var(--text);
}

.node.selected .face,
.node.selected .circle,
.node.selected .diamond {
  border: 2px solid var(--accent);
  box-shadow: 0 0 var(--glow-blur) color-mix(in srgb, var(--accent) var(--glow-mix), transparent);
}

.node.active {
  outline: 2px solid var(--accent);
  outline-offset: 4px;
  border-radius: calc(var(--r-tile) + 4px);
}

.world.far .lines,
.world.far .under,
.world.far .card-pill :deep(.n) {
  visibility: hidden;
}

/* Zoomed out: the pill keeps only its square, larger. */
.world.far .card-pill {
  min-width: 0;
  padding: 0 5px;
}

.world.far .card-pill :deep(.sq) {
  width: 10px;
  height: 10px;
}

.tip {
  position: absolute;
  z-index: 5;
  display: flex;
  flex-direction: column;
  gap: 2px;
  max-width: 320px;
  padding: var(--s-8) var(--s-10);
  background: var(--surface-raised);
  border: 1px solid var(--border-strong);
  border-radius: var(--r-control);
  box-shadow: var(--shadow-sheet);
  font-size: 12px;
  color: var(--text-2);
  pointer-events: none;
}

.tip strong {
  color: var(--text);
  font-weight: 600;
  overflow-wrap: anywhere;
}

.tip .mono {
  font-size: 11px;
}

.tip .fact {
  color: var(--text);
}

.overlay {
  position: absolute;
  left: var(--s-14);
  top: var(--s-14);
  right: var(--s-14);
  z-index: 4;
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-8);
  pointer-events: none;
}

.overlay > :deep(*) {
  pointer-events: auto;
}

.controls {
  position: absolute;
  left: var(--s-14);
  bottom: var(--s-14);
  z-index: 4;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--s-8);
}

.buttons {
  display: flex;
  gap: var(--s-6);
}

.legend-btn {
  height: 32px;
  gap: var(--s-6);
}

.legend-body {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(2, auto);
  gap: var(--s-8) var(--s-16);
  max-width: 420px;
  padding: var(--s-12) var(--s-14);
  background: var(--glass-fill);
  backdrop-filter: var(--glass-blur);
  border: 1px solid var(--border-strong);
  border-radius: var(--r-tile);
  box-shadow: var(--shadow-sheet);
  font-size: 12px;
  color: var(--text-2);
}

.legend-body div {
  display: flex;
  align-items: center;
  gap: var(--s-8);
}

.legend-body .wide {
  grid-column: 1 / -1;
}

.legend-body dd {
  margin: 0;
}

.l {
  stroke: var(--graph-edge);
  stroke-width: 1.6;
}

.l.entry {
  stroke: var(--route-entry);
  stroke-width: 3.2;
}

.l.lateral {
  stroke: var(--route-lateral);
  stroke-width: 2.4;
}

.arrow.entry {
  fill: var(--route-entry);
}

.arrow.lateral {
  fill: var(--route-lateral);
}

.l.dashed {
  stroke-dasharray: 6 4;
}

.l.sec {
  stroke: var(--text-3);
  stroke-width: 2.2;
}

.sw {
  display: inline-block;
  width: 26px;
  height: 12px;
  border-radius: 6px;
  background: var(--graph-node);
  border: 1px solid var(--border-strong);
}

.group-sw {
  background: var(--graph-lane);
  box-shadow: 3px 3px 0 -1px var(--border-strong);
}

.ext-sw {
  background: transparent;
  border: 1px dashed var(--muted);
}

.boundary-sw {
  background: var(--graph-lane);
  border: 1.5px dotted var(--text-3);
}

.sw-tile {
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  border-radius: var(--r-chip);
  color: var(--text-2);
  background: var(--tile);
  border: 1px solid var(--tile-border);
}

.frame-sw {
  border: 1.5px solid var(--sev-critical);
}

.zoom-readout {
  height: 32px;
  min-width: 64px;
  padding: 0 var(--s-8);
  font-size: 12px;
}

.icon-only {
  width: 32px;
  height: 32px;
  padding: 0;
}

.overview {
  position: absolute;
  right: var(--s-14);
  bottom: var(--s-14);
  z-index: 4;
  width: 210px;
  height: 120px;
  overflow: hidden;
  background: color-mix(in srgb, var(--tile) 88%, transparent);
  border: 1px solid var(--border-strong);
  border-radius: var(--r-tile);
  box-shadow: var(--shadow-sheet);
}

.overview svg {
  display: block;
  cursor: pointer;
  touch-action: none;
}

.ov-cap {
  position: absolute;
  top: 5px;
  left: 9px;
  font-size: 9.5px;
  color: var(--text-3);
  pointer-events: none;
}

.ov-line {
  stroke: var(--border-strong);
  stroke-width: 1;
}

.ov-node {
  fill: var(--border-strong);
}

.ov-view {
  fill: var(--accent-wash);
  stroke: var(--accent);
  stroke-width: 1.5;
}

@media (max-width: 899px) {
  .overview {
    display: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .node {
    animation: none;
  }

  .face,
  .tile,
  .line1,
  .circle {
    transition: none;
  }

  .ring {
    animation: none;
    transform: scale(1.3);
    opacity: 0.4;
  }

  .ring.late {
    display: none;
  }
}
</style>
