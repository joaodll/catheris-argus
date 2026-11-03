<script setup lang="ts">
/**
 * Investigate -> Resource map (docs/ui/screens.md, E11; ADR-0033): what a resource connects to,
 * its dependencies and connections, and what each tool says about each resource on the way. It
 * starts from a search or a recently opened resource (MapStart, round M3a); a focus grows one
 * neighbourhood step by step (Expand, group members), at most 500 nodes. Never a whole account.
 * Reach is not judged here: Attack paths and Findings explain it (the owner's decision,
 * 2026-11-01). Everything except expansions lives in the URL (mapQuery).
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
import { forgetRecent, rememberRecent, type RecentResource } from '@/composables/recentResources'
import { username } from '@/composables/useSession'
import MapCanvas from './MapCanvas.vue'
import MapList from './MapList.vue'
import MapPanel from './MapPanel.vue'
import MapStart from './MapStart.vue'
import ResourceSearch from './ResourceSearch.vue'
import { addMember, emptyGraph, factOf, graphNote, MAX_NODES, mergeGraph, noFactNote, nodeName, type GraphState, type MapEdge, type MapNode, type Selection } from './mapGraph'
import { DEPTHS, FACT_LABEL, FACTS, LAYER_LABEL, LAYERS, ORIGIN_LABEL, ORIGINS, chosenLayers, graphParams, mapQueryToUrl, parseMapQuery, type Fact, type MapState, type Origin } from './mapQuery'

const route = useRoute()
const router = useRouter()

// Under 600 px the List view is the default; Map can still be chosen.
const phone = window.matchMedia?.('(max-width: 600px)').matches ?? false
const defaultView = phone ? 'list' : 'map'
const state = computed(() => parseMapQuery(route.query, defaultView))
// A focus is on the canvas; else the start shows.
const started = computed(() => state.value.focus != null)

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
const graphState = ref<Schemas['MapGraphState'] | null>(null)
// The connection the focus neighbourhood was walked in: every Expand stays in it.
const walked = ref<number | null>(null)
let generation = 0
// The selected group or edge (a node's selection is ?open=; see Selection below).
const localSelection = ref<Selection | null>(null)

const neighbourhoodKey = computed(() =>
  JSON.stringify([state.value.focus, state.value.connection, state.value.depth, state.value.layers, state.value.origins]),
)

/** "Recently opened": the focus, once the map has drawn it (it is in the inventory). */
function remember(focus: string, connectionId: number): void {
  const node = graph.value.nodes.get(focus)
  if (!node) return
  rememberRecent(username.value, {
    uid: focus,
    name: node.name ?? null,
    type: node.type ?? null,
    connectionId: node.connection_id ?? connectionId,
    connectionName: connections.data.value?.find((c) => c.id === (node.connection_id ?? connectionId))?.name ?? null,
  })
}

async function load(): Promise<void> {
  const s = state.value
  const mine = ++generation
  graph.value = emptyGraph()
  localSelection.value = null // a group or an edge of the old neighbourhood
  truncated.value = false
  capped.value = false
  notFound.value = false
  error.value = null
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
    graphState.value = result.graph
    remember(s.focus, result.connection_id)
    await showPath(mine)
  } catch (err) {
    if (mine !== generation) return
    if (err instanceof ApiError && (err.status === 404 || err.status === 422)) {
      notFound.value = true
      forgetRecent(username.value, s.focus) // gone from the inventory: not worth reopening
    }
    else error.value = err instanceof ApiError ? err.message : 'Something went wrong while loading.'
  } finally {
    if (mine === generation) loading.value = false
  }
}
watch(neighbourhoodKey, () => void load(), { immediate: true })

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

/** A boundary node becomes the focus in its own connection; anything else stays in this one. */
function focusHere(uid: string): void {
  const node = graph.value.nodes.get(uid)
  navigate({ focus: uid, open: uid, connection: node?.boundary && node.connection_id != null ? node.connection_id : walked.value })
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
const recentLink = (r: RecentResource) => ({ query: mapQueryToUrl({ ...state.value, focus: r.uid, open: r.uid, path: null, connection: r.connectionId }, defaultView) })
const typeLink = (type: string | null) => ({ query: mapQueryToUrl({ ...state.value, type, page: 1 }, defaultView) })
const resourceLink = (r: Schemas['ResourceRow']) => ({
  query: mapQueryToUrl({ ...state.value, focus: r.resource_uid, open: r.resource_uid, path: null, connection: state.value.connection != null ? r.connection_id : null }, defaultView),
})
// Back to the start: the view, the type and its page stay.
const startLink = computed(() => ({ query: mapQueryToUrl({ ...state.value, focus: null, open: null, path: null }, defaultView) }))

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

const alone = computed(() => started.value && !loading.value && graph.value.nodes.size === 1 && graph.value.edges.size === 0 && graph.value.groups.size === 0)
const stale = computed(() => graphNote(graphState.value))
// What Highlight says: about the resources drawn, since a group's members are not.
const drawnNodes = computed(() => [...graph.value.nodes.values()].filter((n) => n.kind === 'resource' || n.kind === 'admin'))
const noFact = computed(() => (state.value.view === 'map' && graph.value.nodes.size ? noFactNote(state.value.highlight, drawnNodes.value) : null))
const factCount = computed(() => drawnNodes.value.filter((n) => factOf(n, state.value.highlight).count > 0).length)
const banner = computed(() => {
  if (truncated.value) return 'This neighbourhood has more than 500 resources. Turn off a layer or lower the depth to see the rest.'
  if (full.value) return 'Showing 500 resources, the most this map draws. Turn off a layer or lower the depth to see the rest.'
  return null
})
const groupCount = computed(() => graph.value.groups.size)
// The loading skeleton's column headers: hop columns, as the canvas draws them (mapLanes.ts).
const canvasLanes = ['2 hops in', '1 hop in', 'Selected', '1 hop out', '2 hops out']
</script>

<template>
  <PageHeader title="Resource map">
    <!-- The map's day, so only with a map: the start says its own under "What's here". -->
    <template v-if="started && dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
  </PageHeader>

  <section v-if="started" class="card toolbar" aria-label="Map controls">
    <ResourceSearch :connection-name="connectionName" @choose="(uid) => navigate({ focus: uid, open: uid, path: null, connection: null })" />
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
    <div v-if="state.view === 'map'" class="field">
      <label class="lbl" for="map-highlight">Highlight</label>
      <select id="map-highlight" class="select" :value="state.highlight ?? ''" @change="navigate({ highlight: (($event.target as HTMLSelectElement).value || null) as Fact | null }, 'replace')">
        <option value="">Nothing</option>
        <option v-for="f in FACTS" :key="f" :value="f">{{ FACT_LABEL[f] }}</option>
      </select>
    </div>
    <div class="field">
      <span id="map-view" class="lbl">View</span>
      <div class="segmented" role="group" aria-labelledby="map-view">
        <button type="button" :aria-pressed="state.view === 'map'" @click="navigate({ view: 'map' }, 'replace')">Map</button>
        <button type="button" :aria-pressed="state.view === 'list'" @click="navigate({ view: 'list' }, 'replace')">List</button>
      </div>
    </div>
    <button type="button" class="btn btn-ghost reset" @click="reset">Reset</button>
  </section>

  <AlertBanner v-if="banner" kind="warn">{{ banner }}</AlertBanner>
  <AlertBanner v-if="started && stale" :kind="stale.kind">{{ stale.text }}</AlertBanner>
  <AlertBanner v-if="path" kind="info">
    Showing attack path {{ path.rule_name ?? path.rule_id }} · <SeverityTag :severity="path.severity" compact />
    <template #action><button type="button" class="btn btn-ghost btn-sm" @click="navigate({ path: null }, 'replace')">Clear</button></template>
  </AlertBanner>
  <AlertBanner v-else-if="pathError" kind="fail">The attack path didn't load: {{ pathError }}</AlertBanner>
  <AlertBanner v-if="noFact" kind="info">{{ noFact }}</AlertBanner>
  <p v-if="state.highlight && !noFact && state.view === 'map'" class="sr-only" role="status">{{ factCount }} of {{ drawnNodes.length }} resources drawn have {{ FACT_LABEL[state.highlight].toLowerCase() }}.</p>
  <AlertBanner v-if="alone" kind="info">No connections in the chosen layers. Turn on Network or IAM policy to see more.</AlertBanner>
  <p v-if="groupCount" class="sr-only" role="status">{{ groupCount }} groups stand for resources not drawn one by one.</p>

  <div class="work" :class="{ 'has-panel': started && !narrow && !!selection }">
    <section class="card canvas-card" :class="{ 'is-map': started && state.view === 'map' }" aria-label="Resource map">
      <MapStart
        v-if="!started"
        :connections="connections.data.value ?? null"
        :connections-failed="!!connections.error.value"
        :connection="state.connection"
        :connection-name="connectionName"
        :recent-link="recentLink"
        :type="state.type"
        :page="state.page"
        :type-link="typeLink"
        :resource-link="resourceLink"
        @choose="(uid, cid) => navigate({ focus: uid, open: uid, path: null, connection: state.connection != null ? cid : null })"
        @account="(cid) => navigate({ connection: cid, page: 1 }, 'replace')"
        @page="(p) => navigate({ page: p }, 'replace')"
      />
      <AlertBanner v-else-if="error" kind="fail" class="in-card">
        The map didn't load: {{ error }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="load">Retry</button></template>
      </AlertBanner>
      <EmptyState v-else-if="notFound" icon="graph" :title="`${state.focus} is not in the inventory.`">
        <RouterLink class="btn btn-secondary" :to="startLink">Find another resource</RouterLink>
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
        :focus="state.focus"
        @select="select"
      />
      <MapCanvas
        v-else
        :graph="graph"
        :focus="state.focus"
        :selection="selection"
        :highlight="highlight"
        :connection-name="connectionName"
        :fact="state.highlight"
        @select="select"
        @expand="expand"
        @focus-here="focusHere"
      >
        <template #overlay>
          <p v-if="!everSelected" class="pill hint">Hover a resource to trace its path · click to open it</p>
        </template>
      </MapCanvas>
    </section>

    <aside v-if="started && !narrow && selection" ref="panelRef" class="card panel" aria-label="Resource panel">
      <MapPanel
        ref="panel"
        :graph="graph"
        :selection="selection"
        :full="full"
        :connection-name="connectionName"
        :connection-id="walked"
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
      :full="full"
      :connection-name="connectionName"
      :connection-id="walked"
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

.reset {
  align-self: flex-end;
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

/* The canvas's pill: the first-use hint. */
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
