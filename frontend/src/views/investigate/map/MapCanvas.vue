<script setup lang="ts">
/**
 * The Resource map's canvas (docs/ui/screens.md, E11, The canvas; design-system.md, Graph).
 *
 * Cytoscape.js (ADR-0033) draws the edges and handles pan, zoom and edge hits. The node pills
 * and the column names are an HTML layer that follows its viewport: a pill needs an icon disc,
 * two type sizes, a finding count and the design tokens, which a canvas label cannot hold. The
 * look is sample B, "path focus" (ADR-0028, sixth amendment): a dot grid that moves with the
 * map, hovering a node traces its path, an overview in the corner. Positions come from mapLanes
 * (Cytoscape's preset layout), so the same view always places a node in the same spot.
 *
 * The canvas is one focusable region: the arrow keys move a keyboard position between nodes,
 * Enter selects, E expands, F makes the focus, Esc clears. The List view is the accessible
 * equivalent of the whole picture.
 */
import cytoscape, { type Core, type EdgeSingular, type ElementDefinition } from 'cytoscape'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import AppIcon from '@/components/AppIcon.vue'
import type { IconName } from '@/components/icons'
import { SEVERITY_COLOR } from '@/views/overview/severity'
import { regionLabel } from '../labels'
import { boundaryLabel, drawnEdges, groupNodeId, nodeName, traceOf, worstOf, worstRank, type GraphState, type MapGroup, type MapNode, type Selection } from './mapGraph'
import { chipSummary, type FlowChip } from './flowGraph'
import { LANE_WIDTH, NODE_HEIGHT, NODE_WIDTH, flowLayout, layout, moveSelection, typeDisc, typeLabel, type LaidNode, type Move, type NodeKind } from './mapLanes'
import { REACH_LABEL, type Reach } from './mapQuery'
import { resolvedTheme } from '@/composables/useTheme'

const props = defineProps<{
  graph: GraphState
  focus: string | null
  selection: Selection | null
  // An attack path (?path=): its nodes and edge ids show in accent, the rest dims.
  highlight: { nodes: string[]; edges: number[] } | null
  connectionName: (id: number) => string
  // Flow mode (ADR-0036): each card's column and the columns' headers; null in Explore.
  flow?: { columns: ReadonlyMap<string, number>; label: (col: number) => string; chips: ReadonlyMap<string, FlowChip[]> } | null
  // Flow mode: the door's reach, named under the internet.
  reach?: Reach | null
}>()
const emit = defineEmits<{ select: [selection: Selection | null]; expand: [uid: string]; focusHere: [uid: string] }>()

/** One card on the canvas: a node of the graph, or a group standing for many. */
interface Card {
  id: string
  kind: NodeKind
  node: MapNode | null
  group: MapGroup | null
  name: string
  type: string | null
  typeLabel: string
  // The icon disc: the type group's colour and glyph.
  color: string
  icon: IconName
  worst: string | null
  open: number
  w: number
  h: number
}

const SIZE: Record<NodeKind, [number, number]> = {
  resource: [NODE_WIDTH, NODE_HEIGHT],
  external: [NODE_WIDTH, NODE_HEIGHT],
  any: [NODE_WIDTH, NODE_HEIGHT],
  group: [NODE_WIDTH, NODE_HEIGHT],
  internet: [56, 56], // a 52 px disc inside
  admin: [48, 48],
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
    const { worst, open } = worstOf(node)
    const [w, h] = SIZE[kind]
    out.push({
      id: node.uid,
      kind,
      node,
      group: null,
      name: nodeName(node),
      type: node.type,
      typeLabel: node.boundary ? boundaryLabel(node, props.connectionName) : kind === 'external' ? 'Not in the inventory' : kind === 'any' ? 'Wildcard grant (*)' : typeLabel(node.type),
      ...typeDisc(kind, node.type),
      worst,
      open,
      w,
      h,
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
      typeLabel: `${group.edge_type} ${group.direction === 'out' ? '←' : '→'} ${anchor ? nodeName(anchor) : group.anchor_uid}`,
      ...typeDisc('group', group.resource_type),
      worst: null,
      open: 0,
      w: NODE_WIDTH,
      h: NODE_HEIGHT,
    })
  }
  return out
})
const byId = computed(() => new Map(cards.value.map((c) => [c.id, c])))
const lines = computed(() => drawnEdges(props.graph))

const laid = computed(() => {
  const laidNodes = cards.value.map<LaidNode>((c) => ({ id: c.id, kind: c.kind, type: c.type, name: c.name, rank: c.node ? worstRank(c.node) : 6 }))
  if (props.flow) return flowLayout(laidNodes, props.flow.columns, props.flow.label)
  return layout(
    laidNodes,
    lines.value.map((l) => ({ source: l.source, target: l.target })),
    props.focus,
  )
})
const laneLabel = computed(() => new Map(laid.value.lanes.map((l) => [l.lane, l.label])))
const chipsOf = (id: string) => chipSummary(props.flow?.chips.get(id) ?? [])

// ---- What is lit: the selection's trace (what reaches it and what it reaches), a highlighted
// path, or, with nothing selected, the hovered node's trace.
const selectedNode = computed(() => (props.selection?.kind === 'node' ? props.selection.id : props.selection?.kind === 'group' ? `group:${props.selection.id}` : null))
const hovered = ref<string | null>(null)
const lit = computed<{ nodes: Set<string>; lines: Set<string> } | null>(() => {
  const sel = props.selection
  if (sel?.kind === 'edge') {
    const line = lines.value.find((l) => l.key === sel.key)
    return line ? { nodes: new Set([line.source, line.target]), lines: new Set([line.key]) } : null
  }
  if (selectedNode.value) return traceOf(lines.value, selectedNode.value)
  if (props.highlight) {
    const edges = new Set(props.highlight.edges)
    return { nodes: new Set(props.highlight.nodes), lines: new Set(lines.value.filter((l) => l.edges.some((e) => edges.has(e.id))).map((l) => l.key)) }
  }
  if (hovered.value && byId.value.has(hovered.value)) return traceOf(lines.value, hovered.value)
  return null
})
const pathLines = computed(() => {
  if (!props.highlight) return new Set<string>()
  const edges = new Set(props.highlight.edges)
  return new Set(lines.value.filter((l) => l.edges.some((e) => edges.has(e.id))).map((l) => l.key))
})
function dimmed(id: string): boolean {
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
 * between lanes, an arc to the right within a lane. Cytoscape takes them as weights along the
 * source-target line and distances along its normal (-dy, dx) / length. */
interface Bend {
  weights: number[]
  distances: number[]
}
function bend(s: { x: number; y: number }, t: { x: number; y: number }): Bend {
  const dx = t.x - s.x
  const dy = t.y - s.y
  const length2 = dx * dx + dy * dy
  if (length2 === 0) return { weights: [0.5], distances: [0] }
  const length = Math.sqrt(length2)
  const points =
    Math.abs(dx) < 1
      ? [{ x: s.x + 72 + Math.abs(dy) * 0.15, y: (s.y + t.y) / 2 }]
      : [
          { x: s.x + dx / 2, y: s.y },
          { x: s.x + dx / 2, y: t.y },
        ]
  return {
    weights: points.map((p) => ((p.x - s.x) * dx + (p.y - s.y) * dy) / length2),
    distances: points.map((p) => ((p.x - s.x) * -dy + (p.y - s.y) * dx) / length),
  }
}

// The reach a door's link from the internet carries when traffic cannot arrive (ADR-0033,
// amended 2026-10-21): drawn in the Traffic layer, labelled.
const VERDICT: Partial<Record<string, string>> = { PUBLIC_RESTRICTED: 'Restricted', PUBLIC_UNVERIFIED: 'Unknown' }

function elements(): ElementDefinition[] {
  const positions = laid.value.positions
  const nodes: ElementDefinition[] = cards.value.map((c) => ({
    group: 'nodes',
    data: { id: c.id, w: c.w, h: c.h, shape: c.kind === 'internet' ? 'ellipse' : c.kind === 'admin' ? 'diamond' : 'round-rectangle' },
    position: { x: positions.get(c.id)!.x, y: positions.get(c.id)!.y },
  }))
  const edges: ElementDefinition[] = lines.value
    .filter((l) => positions.has(l.source) && positions.has(l.target) && l.source !== l.target)
    .map((l) => {
      const { weights, distances } = bend(positions.get(l.source)!, positions.get(l.target)!)
      return { group: 'edges', data: { id: l.key, source: l.source, target: l.target, label: l.type, line: l.style, verdict: VERDICT[l.type], weights, distances } }
    })
  return [...nodes, ...edges]
}

function style(): cytoscape.StylesheetJson {
  const edge = token('--graph-edge')
  const accent = token('--accent')
  const text2 = token('--text-2')
  const canvas = token('--graph-canvas')
  const dim = Number(token('--graph-dim')) || 0.3
  const mono = token('--font-mono')
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
        'font-family': mono,
        'font-size': 10,
        color: text2,
        'text-background-color': canvas,
        'text-background-opacity': 1,
        'text-background-padding': '2px',
        'text-background-shape': 'roundrectangle',
        'text-rotation': 'none',
        label: '',
        // The label rides near the target end of the line: the middle of a short line between
        // two lanes is under the cards, which are drawn above the canvas.
        'target-text-offset': 56,
        // The lit glow: an accent underlay, invisible until an edge is lit.
        'underlay-color': accent,
        'underlay-opacity': 0,
        'underlay-padding': 5,
        'transition-property': 'opacity, line-color, target-arrow-color, width, underlay-opacity',
        'transition-duration': reduced ? 0 : 160,
      } as never,
    },
    { selector: 'edge[line = "dotted"]', style: { 'line-dash-pattern': [1.5, 3] } },
    // A Restricted or Unknown door's link from the internet: fainter and thinner than a
    // reachable one, always labelled with its reach (line style stays the origin's).
    { selector: 'edge[verdict]', style: { width: 1.2, 'line-opacity': 0.55, 'target-label': 'data(verdict)' } as never },
    { selector: 'edge.hover', style: { 'line-color': text2, 'target-arrow-color': text2, 'target-label': 'data(label)' } },
    // Lit (a trace, the selection, a highlighted path): accent, with a soft glow and its label.
    {
      selector: 'edge.lit, edge.path',
      style: { width: 2.4, 'line-color': accent, 'target-arrow-color': accent, 'target-label': 'data(label)', color: accent, 'underlay-opacity': 0.14 } as never,
    },
    { selector: 'edge[verdict].hover, edge[verdict].lit, edge[verdict].path', style: { 'line-opacity': 0.9, 'target-label': 'data(verdict)' } as never },
    { selector: 'edge.dim', style: { opacity: dim } },
  ]
}

function paint(): void {
  const c = cy.value
  if (!c) return
  c.batch(() => {
    c.edges().forEach((e: EdgeSingular) => {
      const key = e.id()
      const isLit = lit.value?.lines.has(key) ?? false
      e.toggleClass('lit', isLit)
      e.toggleClass('path', pathLines.value.has(key))
      e.toggleClass('dim', lit.value != null && !isLit && !pathLines.value.has(key))
    })
  })
}

function rebuild(): void {
  const c = cy.value
  if (!c) return
  c.batch(() => {
    c.elements().remove()
    c.add(elements())
  })
  paint()
}

const MAX_FIT_ZOOM = 1
const FIT_PADDING = 56
/** Fits these elements (all by default), never above 100%: the zoom is worked out first, so an
 * animation ends where it should (capping it after its first frame let it zoom past 100%). */
function fit(eles?: cytoscape.CollectionArgument, animate = false): void {
  const c = cy.value
  if (!c || c.elements().length === 0) return
  const target = c.collection().union(eles ?? c.elements())
  const box = target.boundingBox()
  const level = Math.max(c.minZoom(), Math.min(MAX_FIT_ZOOM, (c.width() - 2 * FIT_PADDING) / Math.max(box.w, 1), (c.height() - 2 * FIT_PADDING) / Math.max(box.h, 1)))
  const viewport = { zoom: level, pan: { x: c.width() / 2 - (box.x1 + box.w / 2) * level, y: c.height() / 2 - (box.y1 + box.h / 2) * level } }
  if (animate && !reduced) c.animate(viewport, { duration: 200, easing: 'ease-out' })
  else c.viewport(viewport)
}

// A flow opens readable: when the whole chain only fits below this zoom (where text hides),
// it opens at this zoom from the internet on the left, and the user pans along the chain.
const FLOW_MIN_ZOOM = 0.8

/** The first view of a graph: everything fitted; a long flow from its start instead. */
function firstView(): void {
  const c = cy.value
  if (!c || c.elements().length === 0) return
  fit()
  if (!props.flow || c.zoom() >= FLOW_MIN_ZOOM) return
  const box = c.elements().boundingBox()
  c.zoom(FLOW_MIN_ZOOM)
  c.pan({ x: 56 - box.x1 * FLOW_MIN_ZOOM, y: c.height() / 2 - ((box.y1 + box.y2) / 2) * FLOW_MIN_ZOOM })
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

function track(instance: Core): void {
  pan.value = { ...instance.pan() }
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
  instance.on('mouseover', 'edge', (event) => event.target.addClass('hover'))
  instance.on('mouseout', 'edge', (event) => event.target.removeClass('hover'))
  cy.value = instance
  known = new Set(cards.value.map((c) => c.id))
  rebuild()
  firstView()
  track(instance)
})
// The canvas narrows when the panel docks (and on window resizes): Cytoscape is told, and the
// selection is brought back into view if the new edge hides it.
let resizeObserver: ResizeObserver | null = null
onMounted(() => {
  if (!region.value || typeof ResizeObserver === 'undefined') return
  resizeObserver = new ResizeObserver(() => {
    const c = cy.value
    if (!c) return
    c.resize()
    track(c)
    const el = selectedNode.value ? c.getElementById(selectedNode.value) : null
    if (!el || el.empty()) return
    const p = el.renderedPosition()
    const half = el.renderedWidth() / 2
    if (p.x - half < 0 || p.x + half > c.width() || p.y < 0 || p.y > c.height()) {
      const viewport = { zoom: c.zoom(), pan: { x: c.width() / 2 - el.position('x') * c.zoom(), y: c.height() / 2 - el.position('y') * c.zoom() } }
      if (reduced) c.viewport(viewport)
      else c.animate(viewport, { duration: 200, easing: 'ease-out' })
    }
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
watch([lit, pathLines], paint)
// The canvas reads the tokens once: a theme change restyles it with the new values.
watch(resolvedTheme, () => {
  void nextTick(() => {
    cy.value?.style(style())
    paint()
  })
})
// A highlighted path is brought into view once its nodes are drawn.
watch(
  () => props.highlight,
  (path) => {
    const c = cy.value
    if (!c || !path) return
    void nextTick(() => {
      const eles = collect(path.nodes)
      if (eles?.nonempty()) fit(eles, true)
    })
  },
)

// ---- The HTML layer, the dot grid and the column names.
const worldStyle = computed(() => ({ transform: `translate(${pan.value.x}px, ${pan.value.y}px) scale(${zoom.value})` }))
const far = computed(() => zoom.value < 0.55)
const GRID = 22
// The dot grid moves and scales with the map.
const regionStyle = computed(() => ({ backgroundSize: `${GRID * zoom.value}px ${GRID * zoom.value}px`, backgroundPosition: `${pan.value.x}px ${pan.value.y}px` }))
// One row of column names, 56 px above the highest node.
const columnNames = computed(() => {
  let top = Infinity
  for (const p of laid.value.positions.values()) top = Math.min(top, p.y)
  if (!Number.isFinite(top)) return []
  return laid.value.lanes.map((l) => ({ lane: l.lane, label: l.label, left: l.x + LANE_WIDTH / 2, top: top - 56 }))
})
function cardStyle(card: Card): Record<string, string> {
  const p = laid.value.positions.get(card.id)
  if (!p) return { display: 'none' }
  return { left: `${p.x - card.w / 2}px`, top: `${p.y - card.h / 2}px`, width: `${card.w}px`, height: `${card.h}px`, '--type': card.color }
}
function countColor(worst: string): Record<string, string> {
  return { '--sev': SEVERITY_COLOR[worst as keyof typeof SEVERITY_COLOR] ?? 'var(--text-2)' }
}
const reachText = computed(() => (props.flow && props.reach ? REACH_LABEL[props.reach] : null))

// Cards sit above the canvas: a wheel over one still zooms the map.
function onWheel(event: WheelEvent): void {
  const c = cy.value
  if (!c || !container.value) return
  event.preventDefault()
  const box = container.value.getBoundingClientRect()
  const level = Math.min(c.maxZoom(), Math.max(c.minZoom(), c.zoom() * Math.pow(1.0015, -event.deltaY)))
  c.zoom({ level, renderedPosition: { x: event.clientX - box.left, y: event.clientY - box.top } })
}

function clickCard(card: Card): void {
  hovered.value = null
  active.value = card.id
  emit('select', card.kind === 'group' && card.group ? { kind: 'group', id: card.group.id } : { kind: 'node', id: card.id })
}

// ---- Hover: traces the node's path at once; a tooltip after 300 ms.
const tip = ref<{ card: Card; x: number; y: number } | null>(null)
let tipTimer: number | undefined
function hover(card: Card, event: MouseEvent): void {
  hovered.value = card.id
  window.clearTimeout(tipTimer)
  const box = region.value?.getBoundingClientRect()
  const target = (event.currentTarget as HTMLElement).getBoundingClientRect()
  tipTimer = window.setTimeout(() => {
    if (box) tip.value = { card, x: target.left - box.left, y: target.bottom - box.top + 6 }
  }, 300)
}
function unhover(): void {
  hovered.value = null
  window.clearTimeout(tipTimer)
  tip.value = null
}
onBeforeUnmount(() => window.clearTimeout(tipTimer))
function toolCount(node: MapNode | null, tool: string): number {
  return node?.findings[tool]?.open ?? 0
}

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
  } else if ((event.key === 'e' || event.key === 'E') && card?.node && !card.node.expanded && !card.node.boundary) {
    emit('expand', card.id)
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
  const findings = card.open ? `${card.open} open findings, worst ${card.worst}` : 'no open findings'
  const chips = chipsOf(card.id).map((c) => c.title)
  const where = lane ? `, ${laneLabel.value.get(lane)} ${props.flow ? 'column' : 'lane'}` : ''
  return `${card.name}, ${card.typeLabel}${where}, ${card.kind === 'group' ? `${card.group?.count} resources` : findings}${chips.length ? `, ${chips.join(', ')}` : ''}.`
})
const regionLabelText = computed(() => `Resource map, ${props.graph.nodes.size} resources. The List view shows the same resources as a table.`)

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
    x1 = Math.min(x1, p.x - card.w / 2)
    x2 = Math.max(x2, p.x + card.w / 2)
    y1 = Math.min(y1, p.y - card.h / 2)
    y2 = Math.max(y2, p.y + card.h / 2)
  }
  if (!Number.isFinite(x1)) return null
  const room = { w: OV.w - 2 * OV.pad, h: OV.h - OV.top - OV.pad }
  const scale = Math.min(room.w / Math.max(x2 - x1, 1), room.h / Math.max(y2 - y1, 1))
  const ox = OV.pad + (room.w - (x2 - x1) * scale) / 2 - x1 * scale
  const oy = OV.top + (room.h - (y2 - y1) * scale) / 2 - y1 * scale
  const blocks = cards.value.flatMap((card) => {
    const p = pos.get(card.id)
    return p ? [{ id: card.id, x: ox + (p.x - card.w / 2) * scale, y: oy + (p.y - card.h / 2) * scale, w: card.w * scale, h: card.h * scale }] : []
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

defineExpose({ fit })
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
      <div
        v-for="card in cards"
        :key="card.id"
        class="node"
        :class="[
          `kind-${card.kind}`,
          {
            focus: card.id === focus,
            selected: card.id === selectedNode,
            active: focused && card.id === active,
            faded: dimmed(card.id),
            onpath: highlight?.nodes.includes(card.id),
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
          <span class="circle"><AppIcon name="globe" :size="26" :stroke="1.5" /></span>
          <span class="under">Internet<template v-if="reachText"> · <span class="reach" :class="`reach-${reach}`">{{ reachText }}</span></template></span>
        </template>
        <template v-else-if="card.kind === 'admin'">
          <span class="diamond"></span>
          <span class="under">{{ card.name }}</span>
        </template>
        <template v-else>
          <span v-if="card.kind === 'group'" class="back"></span>
          <span class="face">
            <span class="disc"><AppIcon :name="card.icon" :size="15" /></span>
            <span class="lines">
              <span class="line1" :class="{ mono: card.kind === 'external' }">
                <template v-if="card.kind === 'group'"><span class="mono">{{ card.group?.count }}</span> {{ card.name }}</template>
                <template v-else>{{ card.name }}</template>
              </span>
              <span class="line2 mono">{{ card.typeLabel }}</span>
            </span>
            <span v-if="card.worst" class="count mono" :style="countColor(card.worst)">{{ card.open }}</span>
          </span>
          <span v-if="chipsOf(card.id).length" class="chips">
            <span v-for="chip in chipsOf(card.id)" :key="chip.kind" class="chip-tag mono" :title="chip.title">{{ chip.text }}</span>
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
      <span v-if="tip.card.node">Prowler {{ toolCount(tip.card.node, 'prowler') }} · CloudFox {{ toolCount(tip.card.node, 'cloudfox') }}</span>
      <span v-if="tip.card.worst">Worst open finding: {{ tip.card.worst }}</span>
    </div>

    <p class="sr-only" aria-live="polite">{{ announcement }}</p>

    <!-- The page's pills (a flow's summary, the first-use hint), top left. -->
    <div class="overlay"><slot name="overlay" /></div>

    <div ref="controlsRef" class="controls" @keydown.esc.stop="legendOpen = false">
      <dl v-show="legendOpen" id="map-legend" class="legend-body">
        <div><dt><svg width="28" height="6" aria-hidden="true"><line x1="0" y1="3" x2="28" y2="3" class="l solid" /></svg></dt><dd>Argus rule</dd></div>
        <div><dt><svg width="28" height="6" aria-hidden="true"><line x1="0" y1="3" x2="28" y2="3" class="l dashed" /></svg></dt><dd>CloudFox only</dd></div>
        <div class="wide"><dt><svg width="28" height="6" aria-hidden="true"><line x1="0" y1="3" x2="28" y2="3" class="l faint" /></svg></dt><dd>Restricted or Unknown door: faint, labelled</dd></div>
        <div><dt><span class="sw node-sw"></span></dt><dd>Resource</dd></div>
        <div><dt><span class="sw group-sw"></span></dt><dd>Group of resources</dd></div>
        <div><dt><span class="sw ext-sw"></span></dt><dd>Not in the inventory</dd></div>
        <div><dt><span class="sw boundary-sw"></span></dt><dd>Other connection or account</dd></div>
        <div class="wide"><dt><span class="sw-disc"><AppIcon name="chip" :size="11" /></span></dt><dd>Icon colour: kind of resource</dd></div>
        <div class="wide"><dt><span class="sw-count mono">3</span></dt><dd>Open findings, coloured by the worst</dd></div>
        <div class="wide"><dd>Data access is what a role's policies allow, not observed traffic.</dd></div>
      </dl>
      <div class="buttons">
        <button type="button" class="btn btn-secondary btn-sm legend-btn" :aria-expanded="legendOpen" aria-controls="map-legend" @click.stop="legendOpen = !legendOpen">
          <AppIcon name="layers" :size="14" />Legend
        </button>
        <button type="button" class="btn btn-secondary icon-only" aria-label="Zoom in" title="Zoom in" @click.stop="zoomBy(1.25)"><AppIcon name="plus" :size="16" /></button>
        <button type="button" class="btn btn-secondary icon-only" aria-label="Zoom out" title="Zoom out" @click.stop="zoomBy(0.8)"><AppIcon name="minus" :size="16" /></button>
        <button type="button" class="btn btn-secondary icon-only" aria-label="Fit" title="Fit" @click.stop="fit()"><AppIcon name="fit" :size="16" /></button>
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
  border-radius: 23px;
}

.face {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 0 10px 0 6px;
  background: var(--graph-node);
  border: 1px solid var(--border-strong);
  transition:
    border-color 160ms,
    box-shadow 160ms;
}

.disc {
  flex: none;
  display: grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  color: var(--type);
  background: color-mix(in srgb, var(--type) 16%, var(--surface-sunken));
  border: 1px solid color-mix(in srgb, var(--type) 45%, transparent);
  transition: opacity 160ms;
}

.lines {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1;
  line-height: 1.25;
}

.line1 {
  font-size: 12.5px;
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
  font-size: 10.5px;
  color: var(--text-3);
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}

/* The open findings: a filled count in the worst severity's colour (6:1 or more on each). */
.count {
  flex: none;
  min-width: 20px;
  height: 20px;
  padding: 0 5px;
  display: grid;
  place-items: center;
  border-radius: 10px;
  background: var(--sev);
  color: var(--on-sev);
  font-size: 10.5px;
  font-weight: 600;
  transition: opacity 160ms;
}

/* Not on the trace: muted, not faded, so its text keeps the contrast floor (WCAG AA). */
.node.faded .face {
  border-color: var(--border);
}

.node.faded .line1,
.node.faded .under {
  color: var(--text-2);
}

.node.faded .disc,
.node.faded .count,
.node.faded .back,
.node.faded .ring {
  opacity: var(--graph-dim);
}

.kind-external .face,
.kind-any .face {
  background: transparent;
  border: 1px dashed var(--muted);
}

/* Another connection's or account's resource: drawn, never expanded (ADR-0033, 2026-10-09). */
.node.boundary .face {
  background: var(--graph-lane);
  border: 1.5px dotted var(--text-3);
}

/* Flow mode: what a node carries (security groups, role, WAF), under its pill. */
.chips {
  position: absolute;
  top: calc(100% + 3px);
  left: 18px;
  display: flex;
  gap: 4px;
  max-width: calc(100% - 18px);
  overflow: hidden;
}

.chip-tag {
  padding: 0 4px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--surface-sunken);
  color: var(--text-2);
  font-size: 10px;
  line-height: 12px;
  white-space: nowrap;
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

.reach {
  font-weight: 600;
}

.reach-open {
  color: var(--status-warn);
}

.reach-restricted {
  color: var(--status-ok);
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
.node.selected .diamond,
.node.onpath .face,
.node.onpath .circle,
.node.onpath .diamond {
  border: 2px solid var(--accent);
  box-shadow: 0 0 var(--glow-blur) color-mix(in srgb, var(--accent) var(--glow-mix), transparent);
}

.node.active {
  outline: 2px solid var(--accent);
  outline-offset: 4px;
  border-radius: 27px;
}

.world.far .lines,
.world.far .under,
.world.far .chips {
  visibility: hidden;
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

.l.dashed {
  stroke-dasharray: 6 4;
}

.l.faint {
  stroke-width: 1.2;
  stroke-opacity: 0.55;
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

.sw-disc {
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  color: var(--type-compute);
  background: color-mix(in srgb, var(--type-compute) 16%, var(--surface-sunken));
  border: 1px solid color-mix(in srgb, var(--type-compute) 45%, transparent);
}

.sw-count {
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  border-radius: 10px;
  background: var(--sev-high);
  color: var(--on-sev);
  font-size: 10.5px;
  font-weight: 600;
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
  .disc,
  .count,
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
