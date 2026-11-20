<script setup lang="ts">
/**
 * Investigate -> Map (ADR-0051; round M, owner 2026-11-15, decisions/0faa077c): one page, two view
 * modes in the URL (`mode`): Infrastructure (the plain map) and Security. The old Resource Map and
 * Security Map menu items are this page; /investigate/security-map redirects to mode=security.
 *
 * What a resource connects to, as a diagram. It starts
 * from a type, a search or a recently opened resource (MapStart). It opens with the resource and
 * its neighbourhood at the chosen depth (1 to 3 hops; the API walks on only from the account's
 * own resources) and grows one hop per click (Expand, group members), at most 500 nodes. Never a
 * whole account.
 * The Infrastructure view draws the resources and how they connect, with no security fact on a card or
 * in the panel, and reads none (the /map/* plain routes), so it also serves as a network and
 * architecture diagram. The Security view reads the same page's sibling routes (`mode=security`): it reads
 * /map/security/*, which adds the security lines and each card's facts (card B, mapFacts.ts),
 * and its panel is the whole resource. Everything except expansions lives in the URL (mapQuery).
 *
 * The third mode, Attack Path (`mode=attack&route=`; W6 §11), is lit only while a route is open:
 * it draws that stored route's steps and nothing else (AttackView). It is entered from a route's
 * page ("Show on map") or the Security panel's Routes tab (Play); Infrastructure, Security or
 * Leave route return to the map, whose depth, connections and filters stayed in the URL.
 */
import { computed, nextTick, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import MultiSelect from '@/components/MultiSelect.vue'
import PageHeader from '@/components/PageHeader.vue'
import SideSheet from '@/components/SideSheet.vue'
import { useResource } from '@/composables/useResource'
import { forgetRecent, rememberRecent, type RecentResource } from '@/composables/recentResources'
import { username } from '@/composables/useSession'
import MapCanvas from './MapCanvas.vue'
import MapList from './MapList.vue'
import MapPanel from './MapPanel.vue'
import MapStart from './MapStart.vue'
import MapTabs from './MapTabs.vue'
import ResourceSearch from './ResourceSearch.vue'
import { addMember, emptyGraph, MAX_NODES, mergeGraph, nodeName, replay, scanLine, withoutExpand, type GraphResponse, type GraphState, type MapEdge, type MapNode, type Selection, type Step } from './mapGraph'
import { DEFAULT_LAYERS, DEPTHS, LAYER_LABEL, LAYERS, chosenLayers, graphParams, mapQueryToUrl, parseMapQuery, type MapKind, type MapState, type ViewMode } from './mapQuery'
import AttackView from './AttackView.vue'
import type { Names } from '../paths/routeWords'
import type { Accounts } from './routeMap'
import type { Viewport } from './mapLanes'

const route = useRoute()
const router = useRouter()
const title = 'Map'

/** One graph read in the chosen view: Infrastructure only ever asks the plain route. */
function readGraph(query: ReturnType<typeof graphParams>) {
  return map.value === 'security'
    ? unwrap(api.GET('/api/v1/map/security/graph', { params: { query } }))
    : unwrap(api.GET('/api/v1/map/graph', { params: { query } }))
}

// Under 600 px the List view is the default; Map can still be chosen.
const phone = window.matchMedia?.('(max-width: 600px)').matches ?? false
const defaultView = phone ? 'list' : 'map'
const state = computed(() => parseMapQuery(route.query, defaultView))
// The view mode: 'resource' is Infrastructure. The Attack Path view's cards are the Security
// view's, so the canvas and the panel see 'security' there.
const map = computed<MapKind>(() => (state.value.mode === 'resource' ? 'resource' : 'security'))
const attack = computed(() => state.value.mode === 'attack' && state.value.route != null)
// A focus is on the canvas; else the start shows.
const started = computed(() => state.value.focus != null)

function navigate(next: Partial<MapState>, how: 'push' | 'replace' = 'push'): void {
  void router[how]({ query: mapQueryToUrl({ ...state.value, ...next }, defaultView) })
}

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
function connectionName(id: number): string {
  return connections.data.value?.find((c) => c.id === id)?.name ?? `Connection ${id}`
}
// Route titles and accounts (the Attack Path view, the Routes tab).
const names: Names = {
  connection: connectionName,
  ofAccount: (account) => connections.data.value?.find((c) => c.account_id === account)?.name ?? null,
}
// The Attack Path view's accounts: where each card is, and which moves cross accounts.
const accounts: Accounts = {
  accountOf: (id) => connections.data.value?.find((c) => c.id === id)?.account_id ?? null,
  connectionOf: (account) => connections.data.value?.find((c) => c.account_id === account)?.id ?? null,
  name: connectionName,
}

// ---- The graph: the focus neighbourhood, then what Expand and group members add.
const graph = shallowRef<GraphState>(emptyGraph())
// The first read and what grew the map since (Expand, a group's member): Collapse draws the map
// again from them without one Expand (mapGraph.replay).
let base: GraphResponse = { nodes: [], edges: [] }
const steps = shallowRef<Step[]>([])
const collapsible = computed(() => new Set(steps.value.flatMap((st) => (st.kind === 'expand' ? [st.uid] : []))))
const loading = ref(false)
const error = ref<string | null>(null)
const notFound = ref(false)
const truncated = ref(false) // the API stopped at 500
const capped = ref(false) // the map holds 500
const dataThrough = ref<string | null>(null)
const days = ref<Schemas['MapDays'] | null>(null)
// The connection the focus neighbourhood was walked in: every Expand stays in it.
const walked = ref<number | null>(null)
let generation = 0
// The selected group or edge (a node's selection is ?open=; see Selection below).
const localSelection = ref<Selection | null>(null)

// The view is in the key: switching it at the same focus reads the other route. The Attack Path
// view reads no neighbourhood.
const neighbourhoodKey = computed(() =>
  JSON.stringify([attack.value ? 'attack' : map.value, state.value.focus, state.value.connection, state.value.depth, state.value.layers]),
)

// ---- The view switch (spec §2): a replace that keeps everything else, and the camera.
const canvas = ref<InstanceType<typeof MapCanvas> | null>(null)
const carried = ref<Viewport | null>(null)
let switching = false
const modeNote = ref('')
function setMode(mode: ViewMode): void {
  if (mode === state.value.mode) return
  // Attack Path is lit only by opening a route (§11.1).
  if (mode === 'attack') return
  // Leaving a route: back to the map as it was. A history push, as Leave route: Back returns to
  // the route.
  if (attack.value) {
    leaveRoute(attackView.value?.leaveTo() ?? null, mode)
    return
  }
  carried.value = canvas.value?.viewport() ?? null
  switching = true
  modeNote.value =
    mode === 'security'
      ? 'Security view: the map now shows misconfigurations, vulnerabilities and security lines.'
      : 'Infrastructure view: resources and how they connect, no security facts.'
  navigate({ mode }, 'replace')
}

// ---- The Attack Path view (§11.1): entering pushes, a step or target change replaces.
const attackView = ref<InstanceType<typeof AttackView> | null>(null)
function playRoute(at: { route: number; target: number; step: number }): void {
  navigate({ mode: 'attack', ...at })
}
function moveRoute(at: { target?: number; step: number }): void {
  navigate({ ...at }, 'replace')
}
/** Leave route: the Security view (or the chosen one), focused on the step's resource when there
 * is one; with none, the map as it was before the route. */
function leaveRoute(focus: string | null, mode: MapKind = 'security'): void {
  modeNote.value = 'Left the route.'
  navigate({ mode, route: null, target: 1, step: 1, ...(focus ? { focus, open: focus, connection: null } : {}) })
}

/** "Recently opened": the focus, once the map has drawn it (it is in the inventory). */
function remember(focus: string, connectionId: number): void {
  const node = graph.value.nodes.get(focus)
  if (!node) return
  rememberRecent(username.value, {
    uid: focus,
    name: node.name ?? null,
    type: node.type ?? null,
    category: node.category ?? null,
    connectionId: node.connection_id ?? connectionId,
    connectionName: connections.data.value?.find((c) => c.id === (node.connection_id ?? connectionId))?.name ?? null,
  })
}

async function load(): Promise<void> {
  const s = state.value
  const mine = ++generation
  // Only a view switch keeps the camera; any other reload opens at the first view.
  if (!switching) carried.value = null
  switching = false
  graph.value = emptyGraph()
  base = { nodes: [], edges: [] }
  steps.value = []
  localSelection.value = null // a group or an edge of the old neighbourhood
  truncated.value = false
  capped.value = false
  notFound.value = false
  error.value = null
  if (!s.focus || attack.value) return
  loading.value = true
  try {
    const result = await readGraph(graphParams(s, s.focus))
    if (mine !== generation) return
    const merged = mergeGraph(emptyGraph(), result)
    base = result
    graph.value = merged.state
    walked.value = result.connection_id
    truncated.value = result.truncated
    capped.value = merged.capped
    dataThrough.value = result.data_through
    days.value = result.days
    remember(s.focus, result.connection_id)
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
    const result = await readGraph(graphParams(state.value, uid, { connection: walked.value, depth: 1 }))
    if (mine !== generation) return
    const merged = mergeGraph(graph.value, result)
    graph.value = merged.state
    steps.value = [...steps.value, { kind: 'expand', uid, response: result }]
    capped.value ||= merged.capped || result.truncated
  } catch (err) {
    if (mine === generation) error.value = err instanceof ApiError ? err.message : 'Something went wrong while expanding.'
  }
}

function add(member: { node: MapNode; edge: MapEdge }): void {
  const merged = addMember(graph.value, member)
  graph.value = merged.state
  steps.value = [...steps.value, { kind: 'add', anchor: member.edge.source_uid === member.node.uid ? member.edge.target_uid : member.edge.source_uid, member }]
  capped.value ||= merged.capped
}

/** Undoes one Expand: the map without it, and without what grew from what it added. */
function collapse(uid: string): void {
  const before = graph.value.nodes.size
  const again = replay(base, withoutExpand(steps.value, uid))
  graph.value = again.state
  steps.value = again.steps
  capped.value = again.capped
  collapsedNote.value = `${graph.value.nodes.get(uid) ? nodeName(graph.value.nodes.get(uid)!) : 'The resource'} collapsed, ${before - again.state.nodes.size} resources removed.`
}
const collapsedNote = ref('')

/** A boundary node becomes the focus in its own connection; anything else stays in this one. */
function focusHere(uid: string): void {
  const node = graph.value.nodes.get(uid)
  navigate({ focus: uid, open: uid, connection: node?.boundary && node.connection_id != null ? node.connection_id : walked.value })
}

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
// The last selection the panel took focus for (see the watch below): a person clearing the
// selection forgets it, so choosing the same card again takes focus again.
let lastSelected: string | null = null
function select(next: Selection | null): void {
  if (next == null) lastSelected = null
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
// From the route (router.ts sets it): the instance outlives a move between the two maps.
const pageTitle = computed(() => `${String(route.meta.title ?? 'Argus')} · Argus`)
const selectedName = computed(() => {
  const sel = selection.value
  if (sel?.kind === 'node') {
    const n = graph.value.nodes.get(sel.id)
    return n ? nodeName(n) : null
  }
  return null
})
watch(
  [selectedName, pageTitle],
  ([name, page]) => {
    document.title = name ? `${name} · ${page}` : page
  },
  { immediate: true },
)

// ---- Toolbar.
const layerOptions = LAYERS.map((l) => ({ value: l, label: LAYER_LABEL[l] }))
function setLayers(values: string[]): void {
  navigate({ layers: chosenLayers(values) })
}
/** Back to the focus and its neighbourhood at the chosen depth: no expansions or selection. */
function reset(): void {
  if (state.value.open) navigate({ open: null }, 'replace')
  void load()
}
// A map opens with the canvas at its full width: the panel comes when a card is chosen (the
// owner asked for more room between the cards, and a docked panel takes a third of it).
const recentLink = (r: RecentResource) => ({ query: mapQueryToUrl({ ...state.value, focus: r.uid, open: null, connection: r.connectionId }, defaultView) })
const typeLink = (type: string | null) => ({ query: mapQueryToUrl({ ...state.value, type, page: 1 }, defaultView) })
const resourceLink = (r: Schemas['ResourceOut']) => ({
  query: mapQueryToUrl({ ...state.value, focus: r.resource_uid, open: null, connection: state.value.connection != null ? r.connection_id : null }, defaultView),
})
// Back to the start: the view, the type and its page stay.
const startLink = computed(() => ({ query: mapQueryToUrl({ ...state.value, focus: null, open: null }, defaultView) }))

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
// Only a new choice moves focus: a reload (a toggle in Connections, a depth) empties the graph
// and brings the same selection back, and taking focus then would close the open menu.
watch(selection, (sel) => {
  if (!sel) return
  const key = JSON.stringify(sel)
  if (key === lastSelected) return
  lastSelected = key
  if (!narrow.value) void nextTick(() => panelRef.value?.querySelector<HTMLElement>('.title')?.focus({ preventScroll: true }))
})

const alone = computed(() => started.value && !loading.value && graph.value.nodes.size === 1 && graph.value.edges.size === 0 && graph.value.groups.size === 0)
// Every kind of connection is already asked for: nothing more to turn on.
const everyLayer = computed(() => state.value.layers.length === LAYERS.length)
const banner = computed(() => {
  if (truncated.value) return 'This neighbourhood has more than 500 resources to draw. Lower the depth or show fewer kinds of connection to see the rest.'
  if (full.value) return 'Showing 500 resources, the most this map draws. Reset, lower the depth or show fewer kinds of connection to see others.'
  return null
})
const groupCount = computed(() => graph.value.groups.size)
// The loading skeleton's rows: tiers, as the canvas draws them (mapLanes.ts).
const skeletonTiers = ['Entry', 'Workloads', 'Data']
const MODES: { mode: ViewMode; label: string; icon: 'graph' | 'shield' | 'route' }[] = [
  { mode: 'resource', label: 'Infrastructure', icon: 'graph' },
  { mode: 'security', label: 'Security', icon: 'shield' },
  { mode: 'attack', label: 'Attack Path', icon: 'route' },
]
</script>

<template>
  <PageHeader :title="title">
    <!-- The map's day, so only with a map: the start says its own under "What's here". -->
    <template v-if="started && !attack && !loading && !notFound && !error">{{ scanLine(days, dataThrough) }}</template>
    <template #actions>
      <div class="field view-mode">
        <span id="map-mode" class="lbl">View</span>
        <div class="segmented" role="group" aria-labelledby="map-mode">
          <button
            v-for="m in MODES"
            :key="m.mode"
            type="button"
            :aria-pressed="state.mode === m.mode"
            :aria-disabled="m.mode === 'attack' && !attack ? 'true' : undefined"
            :aria-describedby="m.mode === 'attack' && !attack ? 'map-attack-hint' : undefined"
            :title="m.mode === 'attack' && !attack ? 'Open a route from Attack paths to see it here' : undefined"
            :class="{ off: m.mode === 'attack' && !attack }"
            @click="setMode(m.mode)"
          >
            <AppIcon :name="m.icon" :size="16" class="mode-icon" />{{ m.label }}
          </button>
        </div>
        <span id="map-attack-hint" class="sr-only">Open a route from Attack paths to see it here.</span>
      </div>
    </template>
  </PageHeader>
  <p class="sr-only" role="status">{{ modeNote }}</p>
  <MapTabs current="map" />

  <AttackView
    v-if="attack"
    ref="attackView"
    :route-id="state.route!"
    :target="state.target"
    :step="state.step"
    :names="names"
    :accounts="accounts"
    @move="moveRoute"
    @leave="leaveRoute"
  />

  <template v-else>
    <section v-if="started" class="card toolbar" aria-label="Map controls">
      <ResourceSearch :connection-name="connectionName" @choose="(uid) => navigate({ focus: uid, open: null, connection: null })" />
      <div class="field">
        <span id="map-depth" class="lbl">Depth</span>
        <div class="segmented" role="group" aria-labelledby="map-depth">
          <button v-for="d in DEPTHS" :key="d" type="button" :aria-pressed="state.depth === d" :aria-label="`${d} ${d === 1 ? 'hop' : 'hops'}`" @click="navigate({ depth: d })">{{ d }}</button>
        </div>
      </div>
      <div class="field">
        <MultiSelect id="map-layers" label="Filters" :options="layerOptions" :model-value="state.layers" select-all :reset-to="DEFAULT_LAYERS" @update:model-value="setLayers" />
      </div>
      <div class="field">
        <span id="map-view" class="lbl">Show as</span>
        <div class="segmented" role="group" aria-labelledby="map-view">
          <button type="button" :aria-pressed="state.view === 'map'" @click="navigate({ view: 'map' }, 'replace')">Map</button>
          <button type="button" :aria-pressed="state.view === 'list'" @click="navigate({ view: 'list' }, 'replace')">List</button>
        </div>
      </div>
      <button type="button" class="btn btn-ghost reset" @click="reset">Reset</button>
    </section>

    <AlertBanner v-if="banner" kind="warn">{{ banner }}</AlertBanner>
    <AlertBanner v-if="alone" kind="info">
      No connections found for this resource on the chosen kinds of connection.
      <template v-if="!everyLayer" #action><button type="button" class="btn btn-secondary btn-sm" @click="setLayers([])">Show every connection</button></template>
    </AlertBanner>
    <p v-if="groupCount" class="sr-only" role="status">{{ groupCount }} groups stand for resources not drawn one by one.</p>
    <p class="sr-only" role="status">{{ collapsedNote }}</p>

    <div class="work" :class="{ 'has-panel': started && !narrow && !!selection }">
      <section class="card canvas-card" :class="{ 'is-map': started && state.view === 'map' }" :aria-label="title">
        <MapStart
          v-if="!started"
          :map="map"
          :connections="connections.data.value ?? null"
          :connections-failed="!!connections.error.value"
          :connection="state.connection"
          :connection-name="connectionName"
          :recent-link="recentLink"
          :type="state.type"
          :page="state.page"
          :type-link="typeLink"
          :resource-link="resourceLink"
          @choose="(uid, cid) => navigate({ focus: uid, open: null, connection: state.connection != null ? cid : null })"
          @account="(cid) => navigate({ connection: cid, page: 1 }, 'replace')"
          @page="(p) => navigate({ page: p }, 'replace')"
        />
        <AlertBanner v-else-if="error" kind="fail" class="in-card">
          The map didn't load: {{ error }}
          <template #action><button type="button" class="btn btn-secondary btn-sm" @click="load">Retry</button></template>
        </AlertBanner>
        <EmptyState v-else-if="notFound" icon="graph" title="This resource is not in the inventory or on any connection." :text="state.focus ?? undefined">
          <RouterLink class="btn btn-secondary" :to="startLink">Find another resource</RouterLink>
        </EmptyState>
        <div v-else-if="loading && graph.nodes.size === 0" class="skeleton-map" aria-busy="true" aria-label="Loading the map">
          <div v-for="tier in skeletonTiers" :key="tier" class="sk-tier">
            <span class="eyebrow">{{ tier }}</span>
            <div v-for="n in 3" :key="n" class="sk-node"></div>
          </div>
        </div>
        <MapList
          v-else-if="state.view === 'list'"
          :map="map"
          :graph="graph"
          :selection="selection"
          :focus="state.focus"
          @select="select"
        />
        <MapCanvas
          v-else
          ref="canvas"
          :map="map"
          :graph="graph"
          :focus="state.focus"
          :selection="selection"
          :connection-name="connectionName"
          :collapsible="collapsible"
          :initial-viewport="carried"
          @select="select"
          @expand="expand"
          @collapse="collapse"
          @focus-here="focusHere"
        >
          <template #overlay>
            <p v-if="!everSelected" class="pill hint">Click a resource to open it · Expand adds what it connects to</p>
          </template>
        </MapCanvas>
      </section>

      <aside v-if="started && !narrow && selection" ref="panelRef" class="card panel" aria-label="Resource panel">
        <MapPanel
          ref="panel"
          :map="map"
          :graph="graph"
          :selection="selection"
          :full="full"
          :collapsible="collapsible"
          :tab="state.tab"
          :connection-name="connectionName"
          :connection-id="walked"
          :names="names"
          @tab="(t) => navigate({ tab: t }, 'replace')"
          @close="select(null)"
          @collapse="collapse"
          @expand="expand"
          @focus-here="focusHere"
          @add="add"
          @select="select"
          @play="playRoute"
        />
      </aside>
    </div>

    <SideSheet v-if="narrow && selection" :title="sheetTitle" :description="sheetCaption" @close="select(null)">
      <MapPanel
        ref="panel"
        :map="map"
        framed
        :graph="graph"
        :selection="selection"
        :full="full"
        :collapsible="collapsible"
        :tab="state.tab"
        :connection-name="connectionName"
        :connection-id="walked"
        :names="names"
        @tab="(t) => navigate({ tab: t }, 'replace')"
        @close="select(null)"
        @collapse="collapse"
        @expand="expand"
        @focus-here="focusHere"
        @add="add"
        @select="select"
        @play="playRoute"
      />
    </SideSheet>
  </template>
</template>

<style scoped>
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--s-12) var(--s-16);
  padding: var(--s-16);
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

/* The View switch (round M, spec §2): on the header's right, on the start too. */
.view-mode .segmented button {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

/* Attack Path with no route open: it says how to light it (title, hint), and does nothing. */
.view-mode .segmented button.off {
  color: var(--text-3);
  cursor: not-allowed;
}

@media (max-width: 599px) {
  .view-mode,
  .view-mode .segmented {
    width: 100%;
  }

  .view-mode .segmented button {
    flex: 1;
    justify-content: center;
  }

  .mode-icon {
    display: none;
  }
}

/* The loading skeleton: tier rows, as the canvas draws them (mapLanes.ts, 208 x 64 cards). */
.skeleton-map {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 64px;
  flex: 1;
  min-height: 600px;
  padding-top: var(--s-48);
  overflow: hidden;
  background-color: var(--graph-canvas);
  background-image: radial-gradient(circle, var(--graph-dot) 1px, transparent 1.2px);
  background-size: 22px 22px;
}

.sk-tier {
  position: relative;
  display: flex;
  gap: 40px;
}

.sk-tier .eyebrow {
  position: absolute;
  right: calc(100% + 32px);
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-3);
  letter-spacing: 0.12em;
}

.sk-node {
  width: 208px;
  height: 64px;
  border-radius: var(--r-tile);
  background: var(--surface-raised);
}
</style>
