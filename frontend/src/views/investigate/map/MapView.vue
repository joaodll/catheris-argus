<script setup lang="ts">
/**
 * Investigate -> Resource map (docs/ui/screens.md, E11; ADR-0033, ADR-0036): what a resource
 * connects to, from the internet down to data and identity, and what each tool says about each
 * resource on the way. It starts from the front doors list; a door opens its Flow, the whole
 * chain from that internet entry, computed in ingest. Explore grows one neighbourhood step by
 * step (Expand, group members), at most 500 nodes; it opens from a node ("Explore around"), a
 * door no flow starts from, or Search. There is no mode switch: what is open says the mode
 * (argus_v11). Never a whole account. Everything except expansions lives in the URL (mapQuery).
 */
import { computed, nextTick, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import MultiSelect from '@/components/MultiSelect.vue'
import PageHeader from '@/components/PageHeader.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import SideSheet from '@/components/SideSheet.vue'
import { useResource } from '@/composables/useResource'
import FrontDoors from './FrontDoors.vue'
import MapCanvas from './MapCanvas.vue'
import MapList from './MapList.vue'
import MapPanel from './MapPanel.vue'
import ResourceSearch from './ResourceSearch.vue'
import { columnLabel, flowView, type FlowView } from './flowGraph'
import { addMember, drawnEdges, emptyGraph, MAX_NODES, mergeGraph, nodeName, pathFromInternet, worstOf, type GraphState, type MapEdge, type MapNode, type Selection } from './mapGraph'
import {
  DEPTHS,
  LAYER_LABEL,
  LAYERS,
  ORIGIN_LABEL,
  ORIGINS,
  chosenLayers,
  graphParams,
  mapQueryToUrl,
  modeOf,
  parseMapQuery,
  type MapState,
  type Origin,
} from './mapQuery'

const route = useRoute()
const router = useRouter()

// Under 600 px the List view is the default; Map can still be chosen.
const phone = window.matchMedia?.('(max-width: 600px)').matches ?? false
const defaultView = phone ? 'list' : 'map'
const state = computed(() => parseMapQuery(route.query, defaultView))
const mode = computed(() => modeOf(state.value))

function navigate(next: Partial<MapState>, how: 'push' | 'replace' = 'push'): void {
  void router[how]({ query: mapQueryToUrl({ ...state.value, ...next }, defaultView) })
}

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
function connectionName(id: number): string {
  return connections.data.value?.find((c) => c.id === id)?.name ?? `Connection ${id}`
}

// ---- The graph: the focus neighbourhood, then what Expand and group members add.
const graph = shallowRef<GraphState>(emptyGraph())
const loading = ref(false)
const error = ref<string | null>(null)
const notFound = ref(false)
const truncated = ref(false) // the API stopped at 500
const capped = ref(false) // the map holds 500
const dataThrough = ref<string | null>(null)
// The connection the focus neighbourhood was walked in: every Expand stays in it.
const walked = ref<number | null>(null)
// Flow mode: the flow on the canvas, its columns and chips.
const flow = shallowRef<FlowView | null>(null)
const flowEntry = ref<string | null>(null)
const flowTruncated = ref(false)
const flowReach = ref<Schemas['FlowDetail']['reach'] | null>(null)
let generation = 0
// The selected group or edge (a node's selection is ?open=; see Selection below).
const localSelection = ref<Selection | null>(null)

const neighbourhoodKey = computed(() =>
  mode.value === 'flow'
    ? JSON.stringify(['flow', state.value.flow, state.value.asOf])
    : JSON.stringify(['explore', state.value.focus, state.value.connection, state.value.depth, state.value.layers, state.value.origins, state.value.asOf]),
)

async function load(): Promise<void> {
  const s = state.value
  const mine = ++generation
  graph.value = emptyGraph()
  localSelection.value = null // a group or an edge of the old neighbourhood
  truncated.value = false
  capped.value = false
  notFound.value = false
  error.value = null
  flow.value = null
  flowEntry.value = null
  flowTruncated.value = false
  flowReach.value = null
  if (s.flow != null) {
    await loadFlow(s.flow, mine)
    return
  }
  if (!s.focus) return
  loading.value = true
  try {
    const result = await unwrap(api.GET('/api/v1/map/graph', { params: { query: graphParams(s, s.focus) } }))
    if (mine !== generation) return
    const merged = mergeGraph(emptyGraph(), result)
    graph.value = merged.state
    walked.value = result.connection_id
    truncated.value = result.truncated
    capped.value = merged.capped
    dataThrough.value = result.data_through
    await showPath(mine)
  } catch (err) {
    if (mine !== generation) return
    if (err instanceof ApiError && (err.status === 404 || err.status === 422)) notFound.value = true
    else error.value = err instanceof ApiError ? err.message : 'Something went wrong while loading.'
  } finally {
    if (mine === generation) loading.value = false
  }
}
watch(neighbourhoodKey, () => void load(), { immediate: true })

async function loadFlow(id: number, mine: number): Promise<void> {
  loading.value = true
  try {
    const detail = await unwrap(api.GET('/api/v1/map/flows/{flow_id}', { params: { path: { flow_id: id }, query: { as_of: state.value.asOf } } }))
    if (mine !== generation) return
    const view = flowView(detail)
    flow.value = view
    graph.value = view.graph
    walked.value = detail.connection_id
    flowEntry.value = detail.entry_uid
    flowTruncated.value = detail.truncated
    flowReach.value = detail.reach
    dataThrough.value = detail.data_through
  } catch (err) {
    if (mine !== generation) return
    if (err instanceof ApiError && err.status === 404) notFound.value = true
    else error.value = err instanceof ApiError ? err.message : 'Something went wrong while loading.'
  } finally {
    if (mine === generation) loading.value = false
  }
}
const canvasFlow = computed(() => {
  const view = flow.value
  return view ? { columns: view.columns, label: (col: number) => columnLabel(col, view.entryCol), chips: view.chips } : null
})
const flowLink = (id: number) => ({ query: mapQueryToUrl({ ...state.value, flow: id, focus: null, open: null, path: null }, defaultView) })
// Back to the front doors list as it was: its filters and page are in the URL. Its connection
// too, unless Search cleared it (the API then walks the focus's own): then the one walked.
const doorsLink = computed(() => ({ query: mapQueryToUrl({ ...state.value, flow: null, focus: null, open: null, path: null, connection: state.value.connection ?? walked.value }, defaultView) }))
const flowName = computed(() => {
  const entry = flowEntry.value ? graph.value.nodes.get(flowEntry.value) : undefined
  return entry ? nodeName(entry) : null
})
// The flow's summary pill: its resources and their open findings over both tools.
const flowCounts = computed(() => {
  let resources = 0
  let open = 0
  for (const node of graph.value.nodes.values()) {
    if (node.kind !== 'resource') continue
    resources += 1
    open += worstOf(node).open
  }
  return { resources, open }
})
// "Path from the internet" (Flow mode, a node selected): the shortest chain along the flow.
const flowPath = computed(() => {
  const sel = selection.value
  if (mode.value !== 'flow' || sel?.kind !== 'node') return null
  const steps = pathFromInternet(drawnEdges(graph.value), sel.id)
  return steps?.flatMap((step) => {
    const node = graph.value.nodes.get(step.uid)
    const role = step.line?.type === 'USES' ? step.line.edges[0]?.attributes.via_role : undefined
    return node ? [{ node, via: typeof role === 'string' ? role : null }] : []
  }) ?? null
})

const full = computed(() => capped.value || graph.value.nodes.size + graph.value.groups.size >= MAX_NODES)

async function expand(uid: string): Promise<void> {
  if (full.value) return
  const mine = generation
  try {
    const result = await unwrap(api.GET('/api/v1/map/graph', { params: { query: graphParams(state.value, uid, 1, walked.value) } }))
    if (mine !== generation) return
    const merged = mergeGraph(graph.value, result)
    graph.value = merged.state
    capped.value ||= merged.capped || result.truncated
  } catch (err) {
    if (mine === generation) error.value = err instanceof ApiError ? err.message : 'Something went wrong while expanding.'
  }
}

function add(member: { node: MapNode; edge: MapEdge }): void {
  const merged = addMember(graph.value, member)
  graph.value = merged.state
  capped.value ||= merged.capped
}

/** A boundary node becomes the focus in its own connection; anything else stays in this one.
 * From a flow, this is "Explore around": the node's neighbourhood in Explore. */
function focusHere(uid: string): void {
  const node = graph.value.nodes.get(uid)
  navigate({ flow: null, focus: uid, open: uid, connection: node?.boundary && node.connection_id != null ? node.connection_id : walked.value })
}

// ---- A highlighted attack path (?path=): its steps are added to the map, then lit.
const path = shallowRef<Schemas['PathDetail'] | null>(null)
const pathError = ref<string | null>(null)
async function showPath(mine: number): Promise<void> {
  const id = state.value.path
  if (id == null) {
    path.value = null
    return
  }
  try {
    const detail = await unwrap(api.GET('/api/v1/attack-paths/{path_id}', { params: { path: { path_id: id } } }))
    if (mine !== generation) return
    path.value = detail
    pathError.value = null
    const merged = mergeGraph(graph.value, { nodes: detail.nodes, edges: detail.edges })
    graph.value = merged.state
    capped.value ||= merged.capped
  } catch (err) {
    if (mine === generation) pathError.value = err instanceof ApiError ? err.message : 'The attack path did not load.'
  }
}
watch(
  () => state.value.path,
  () => void showPath(generation),
)
const highlight = computed(() => (path.value ? { nodes: path.value.node_uids, edges: path.value.edges.map((e) => e.id) } : null))

// ---- Selection: a node is in the URL (?open=), a group or an edge only on the page.
const selection = computed<Selection | null>(() => {
  if (localSelection.value) return localSelection.value
  const open = state.value.open
  return open && graph.value.nodes.has(open) ? { kind: 'node', id: open } : null
})
// The first-use hint stays until something is selected once.
const everSelected = ref(false)
watch(selection, (sel) => {
  if (sel) everSelected.value = true
}, { immediate: true })
function select(next: Selection | null): void {
  if (next?.kind === 'node') {
    localSelection.value = null
    if (state.value.open !== next.id) navigate({ open: next.id }, 'replace')
  } else {
    localSelection.value = next
    if (state.value.open) navigate({ open: null }, 'replace')
  }
}
watch(
  () => state.value.open,
  (open) => {
    if (open) localSelection.value = null
  },
)
// The panel's title takes focus when the selection changes from the List view or the panel.
const panelRef = ref<HTMLElement | null>(null)

// The open resource's name goes in front of the page title.
const pageTitle = document.title
const selectedName = computed(() => {
  const sel = selection.value
  if (sel?.kind === 'node') {
    const n = graph.value.nodes.get(sel.id)
    return n ? nodeName(n) : null
  }
  return null
})
watch(
  selectedName,
  (name) => {
    document.title = name ? `${name} · ${pageTitle}` : pageTitle
  },
  { immediate: true },
)

// ---- Toolbar.
const layerOptions = LAYERS.map((l) => ({ value: l, label: LAYER_LABEL[l] }))
function setLayers(values: string[]): void {
  navigate({ layers: chosenLayers(values) })
}
function toggleOrigin(origin: Origin): void {
  const on = state.value.origins.includes(origin)
  if (on && state.value.origins.length === 1) return // one origin stays on
  navigate({ origins: on ? state.value.origins.filter((o) => o !== origin) : ORIGINS.filter((o) => o === origin || state.value.origins.includes(o)) })
}
/** Back to the focus alone at the chosen depth: no expansions, selection or path. */
function reset(): void {
  if (state.value.open || state.value.path) navigate({ open: null, path: null }, 'replace')
  void load()
}
const focusLink = (uid: string) => ({ query: mapQueryToUrl({ ...state.value, flow: null, focus: uid, open: null, path: null }, defaultView) })

// ---- Panel frame: docked (≥ 1200 px), over the canvas (900–1200), the detail sheet (< 900).
const narrow = ref(window.matchMedia?.('(max-width: 899px)').matches ?? false)
const media = window.matchMedia?.('(max-width: 899px)')
const onMedia = (): void => {
  narrow.value = media?.matches ?? false
}
media?.addEventListener('change', onMedia)
onBeforeUnmount(() => media?.removeEventListener('change', onMedia))
const panel = ref<InstanceType<typeof MapPanel> | null>(null)
const sheetTitle = computed(() => (panel.value?.title as string | undefined) ?? 'Resource')
const sheetCaption = computed(() => (panel.value?.caption as string | undefined) ?? '')
watch(selection, (sel, before) => {
  if (sel && !narrow.value && JSON.stringify(sel) !== JSON.stringify(before)) {
    void nextTick(() => panelRef.value?.querySelector<HTMLElement>('.title')?.focus({ preventScroll: true }))
  }
})

const alone = computed(() => mode.value === 'explore' && !loading.value && state.value.focus != null && graph.value.nodes.size === 1 && graph.value.edges.size === 0 && graph.value.groups.size === 0)
const banner = computed(() => {
  if (flowTruncated.value) return 'This flow reaches more than the map draws (150 resources, 10 steps). Explore around a resource to see the rest.'
  if (truncated.value) return 'This neighbourhood has more than 500 resources. Turn off a layer or lower the depth to see the rest.'
  if (full.value) return 'Showing 500 resources, the most this map draws. Turn off a layer or lower the depth to see the rest.'
  return null
})
const groupCount = computed(() => graph.value.groups.size)
// A flow or a focus is on the canvas (else the start list shows).
const started = computed(() => mode.value !== 'doors')
// The loading skeleton's column headers: hop columns, as the canvas draws them (mapLanes.ts).
const canvasLanes = ['2 hops in', '1 hop in', 'Selected', '1 hop out', '2 hops out']
</script>

<template>
  <PageHeader title="Resource map">
    <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
  </PageHeader>

  <section class="card toolbar" aria-label="Map controls">
    <RouterLink v-if="started" class="btn btn-secondary back" :to="doorsLink"><AppIcon name="chevron" class="back-chev" :size="16" :stroke="2.2" />Front doors</RouterLink>
    <ResourceSearch :connection-name="connectionName" @choose="(uid) => navigate({ flow: null, focus: uid, open: uid, path: null, connection: null })" />
    <template v-if="mode === 'explore'">
      <div class="field">
        <span id="map-depth" class="lbl">Depth</span>
        <div class="segmented" role="group" aria-labelledby="map-depth">
          <button v-for="d in DEPTHS" :key="d" type="button" :aria-pressed="state.depth === d" @click="navigate({ depth: d })">{{ d }}</button>
        </div>
      </div>
      <div class="field">
        <MultiSelect id="map-layers" label="Layers" :options="layerOptions" :model-value="state.layers" @update:model-value="setLayers" />
      </div>
      <div class="field">
        <span id="map-origins" class="lbl">Origins</span>
        <div class="origins" role="group" aria-labelledby="map-origins">
          <button
            v-for="o in ORIGINS"
            :key="o"
            type="button"
            class="toggle-chip"
            :aria-pressed="state.origins.includes(o)"
            :disabled="state.origins.includes(o) && state.origins.length === 1"
            :title="state.origins.includes(o) && state.origins.length === 1 ? 'One origin stays on' : undefined"
            @click="toggleOrigin(o)"
          >
            <AppIcon v-if="state.origins.includes(o)" name="check" :size="14" :stroke="2.2" />{{ ORIGIN_LABEL[o] }}
          </button>
        </div>
      </div>
    </template>
    <div class="field">
      <label class="lbl" for="map-asof">As of</label>
      <input id="map-asof" class="input" type="date" :value="state.asOf ?? ''" :max="new Date().toISOString().slice(0, 10)" @change="navigate({ asOf: ($event.target as HTMLInputElement).value || null })">
    </div>
    <div v-if="started" class="field">
      <span id="map-view" class="lbl">View</span>
      <div class="segmented" role="group" aria-labelledby="map-view">
        <button type="button" :aria-pressed="state.view === 'map'" @click="navigate({ view: 'map' }, 'replace')">Map</button>
        <button type="button" :aria-pressed="state.view === 'list'" @click="navigate({ view: 'list' }, 'replace')">List</button>
      </div>
    </div>
    <button v-if="mode === 'explore'" type="button" class="btn btn-ghost reset" @click="reset">Reset</button>
  </section>

  <AlertBanner v-if="banner" kind="warn">{{ banner }}</AlertBanner>
  <AlertBanner v-if="path" kind="info">
    Showing attack path {{ path.rule_name ?? path.rule_id }} · <SeverityTag :severity="path.severity" compact />
    <template #action><button type="button" class="btn btn-ghost btn-sm" @click="navigate({ path: null }, 'replace')">Clear</button></template>
  </AlertBanner>
  <AlertBanner v-else-if="pathError" kind="fail">The attack path didn't load: {{ pathError }}</AlertBanner>
  <AlertBanner v-if="alone" kind="info">No connections in the chosen layers. Turn on Network or IAM policy to see more.</AlertBanner>
  <p v-if="groupCount" class="sr-only" role="status">{{ groupCount }} groups stand for resources not drawn one by one.</p>

  <div class="work" :class="{ 'has-panel': started && !narrow && !!selection }">
    <section class="card canvas-card" :class="{ 'is-map': started && state.view === 'map' }" aria-label="Resource map">
      <FrontDoors
        v-if="!started"
        :connections="connections.data.value ?? []"
        :state="state"
        :focus-link="focusLink"
        :flow-link="flowLink"
        @change="(next) => navigate(next, 'replace')"
      />
      <AlertBanner v-else-if="error" kind="fail" class="in-card">
        The map didn't load: {{ error }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="load">Retry</button></template>
      </AlertBanner>
      <EmptyState v-else-if="notFound && mode === 'flow'" icon="graph" :title="`This flow has no data on ${state.asOf ?? 'the latest day'}.`">
        <RouterLink class="btn btn-secondary" :to="doorsLink">Back to front doors</RouterLink>
      </EmptyState>
      <EmptyState v-else-if="notFound" icon="graph" :title="`${state.focus} is not in the inventory on ${state.asOf ?? 'the latest day'}.`">
        <RouterLink class="btn btn-secondary" :to="doorsLink">Back to front doors</RouterLink>
      </EmptyState>
      <div v-else-if="loading && graph.nodes.size === 0" class="skeleton-map" aria-busy="true" aria-label="Loading the map">
        <div v-for="(lane, i) in canvasLanes" :key="lane" class="sk-lane">
          <span class="eyebrow">{{ lane }}</span>
          <template v-if="i >= 1 && i <= 3"><div v-for="n in 3" :key="n" class="sk-node"></div></template>
        </div>
      </div>
      <MapList
        v-else-if="state.view === 'list'"
        :graph="graph"
        :selection="selection"
        :focus="mode === 'flow' ? flowEntry : state.focus"
        :flow="canvasFlow"
        @select="select"
      />
      <MapCanvas
        v-else
        :graph="graph"
        :focus="mode === 'flow' ? flowEntry : state.focus"
        :flow="canvasFlow"
        :selection="selection"
        :highlight="highlight"
        :connection-name="connectionName"
        :reach="flowReach"
        @select="select"
        @expand="expand"
        @focus-here="focusHere"
      >
        <template #overlay>
          <p v-if="flowName && mode === 'flow'" class="pill" role="status">
            Flow from <strong>{{ flowName }}</strong> · <span class="mono">{{ flowCounts.resources }}</span> {{ flowCounts.resources === 1 ? 'resource' : 'resources' }} ·
            <template v-if="flowCounts.open"><span class="mono">{{ flowCounts.open }}</span> open {{ flowCounts.open === 1 ? 'finding' : 'findings' }}</template><template v-else>no open findings</template>
          </p>
          <p v-if="!everSelected" class="pill hint">Hover a resource to trace its path · click to open it</p>
        </template>
      </MapCanvas>
    </section>

    <aside v-if="started && !narrow && selection" ref="panelRef" class="card panel" aria-label="Resource panel">
      <MapPanel
        ref="panel"
        :graph="graph"
        :selection="selection"
        :as-of="state.asOf"
        :full="full"
        :connection-name="connectionName"
        :connection-id="walked"
        :flow-chips="flow?.chips ?? null"
        :flow-path="flowPath"
        @close="select(null)"
        @expand="expand"
        @focus-here="focusHere"
        @add="add"
        @select="select"
      />
    </aside>
  </div>

  <SideSheet v-if="narrow && selection" :title="sheetTitle" :description="sheetCaption" @close="select(null)">
    <MapPanel
      ref="panel"
      framed
      :graph="graph"
      :selection="selection"
      :as-of="state.asOf"
      :full="full"
      :connection-name="connectionName"
      :connection-id="walked"
      :flow-chips="flow?.chips ?? null"
      :flow-path="flowPath"
      @close="select(null)"
      @expand="expand"
      @focus-here="focusHere"
      @add="add"
      @select="select"
    />
  </SideSheet>
</template>

<style scoped>
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--s-12) var(--s-16);
  padding: var(--s-16);
}

.origins {
  display: flex;
  gap: var(--s-6);
}

.toggle-chip {
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
  height: var(--control-h);
  padding: 0 var(--s-12);
  border: 1px solid var(--border-control);
  border-radius: var(--r-control);
  background: var(--surface-sunken);
  color: var(--text-2);
  font-size: 13px;
  cursor: pointer;
}

.toggle-chip[aria-pressed='true'] {
  background: var(--surface-raised);
  color: var(--text);
  font-weight: 600;
}

.toggle-chip:disabled {
  cursor: not-allowed;
}

.reset,
.back {
  align-self: flex-end;
}

.back {
  gap: var(--s-6);
}

.back-chev {
  transform: rotate(180deg);
}

.work {
  --map-h: clamp(600px, calc(100vh - 280px), 960px);

  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: var(--s-16);
  min-height: calc(100vh - 320px);
}

/* The panel docks only while something is selected (sample B, 2026-10-14). */
.work.has-panel {
  grid-template-columns: minmax(0, 1fr) 400px;
}

.canvas-card {
  display: flex;
  flex-direction: column;
  min-height: 600px;
  padding: 0;
  overflow: hidden;
}

/* The drawn map keeps one height, whatever the panel beside it holds. */
.canvas-card.is-map {
  height: var(--map-h);
  align-self: start;
}

/* The canvas's pills: the flow's summary and the first-use hint. */
.pill {
  margin: 0;
  padding: var(--s-4) var(--s-12);
  border-radius: var(--r-pill);
  background: var(--glass-fill);
  backdrop-filter: var(--glass-blur);
  border: 1px solid var(--border);
  font-size: 12.5px;
  color: var(--text-2);
}

.pill strong {
  color: var(--text);
}

.in-card {
  margin: var(--s-16);
}

.panel {
  padding: var(--s-20);
  max-height: var(--map-h);
  overflow-y: auto;
  position: sticky;
  top: var(--s-16);
  align-self: start;
}

/* 900–1200 px: the panel lies over the right of the canvas (still not modal). */
@media (max-width: 1199px) {
  .work.has-panel {
    grid-template-columns: minmax(0, 1fr);
  }

  .panel {
    position: absolute;
    top: 0;
    right: 0;
    width: 400px;
    max-height: 100%;
    box-shadow: var(--shadow-sheet);
    z-index: 6;
  }
}

.skeleton-map {
  display: flex;
  justify-content: center;
  gap: 28px;
  flex: 1;
  min-height: 600px;
  padding-top: var(--s-48);
  background-color: var(--graph-canvas);
  background-image: radial-gradient(circle, var(--graph-dot) 1px, transparent 1.2px);
  background-size: 22px 22px;
}

.sk-lane {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 24px;
  width: 178px;
}

.sk-lane .eyebrow {
  color: var(--text-3);
  letter-spacing: 0.12em;
  margin-bottom: var(--s-24);
}

.sk-node {
  width: 178px;
  height: 46px;
  border-radius: 23px;
  background: var(--surface-raised);
}

@media (max-width: 899px) {
  .skeleton-map {
    overflow: hidden;
  }
}
</style>
