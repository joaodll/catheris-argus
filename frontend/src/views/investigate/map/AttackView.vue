<script setup lang="ts">
/**
 * The Map's Attack Path view (ADR-0052 as amended 2026-11-15; spec W6 §4, §11): one stored
 * route's chosen target, drawn from its own steps only (routeMap.ts), never the map's
 * neighbourhood. The player replaces the map's toolbar and opens paused; the step list, in the
 * panel's place, is the canvas's accessible equivalent and carries each step's evidence and fix.
 * Everything is in the URL (route, target, step); MapView owns it, this view asks for changes.
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import { useResource } from '@/composables/useResource'
import { utc } from '@/format'
import { SEVERITY_LABEL } from '@/views/overview/severity'
import { LEVEL_LABEL, LEVEL_MEANING, type StepLevel } from '../paths/routeClass'
import StepEvidence from '../paths/StepEvidence.vue'
import { moveWords, nodeLabel, routeTitle, selfStepTitle, type Names, type StepNode, type StepOut } from '../paths/routeWords'
import MapCanvas from './MapCanvas.vue'
import type { GraphState, MapNode, Selection } from './mapGraph'
import { crossings, isMove, leaveFocus, routeDrawing, stepAnnouncement, stepAtCard, type Accounts } from './routeMap'

const props = defineProps<{ routeId: number; target: number; step: number; names: Names; accounts: Accounts }>()
const emit = defineEmits<{
  // A new target or step: the URL is replaced (Back leaves the route).
  move: [at: { target?: number; step: number }]
  // Leave route: the Security view, focused on this resource (null: the Map's start).
  leave: [focus: string | null]
}>()

const detail = useResource(
  async () => {
    try {
      return await unwrap(api.GET('/api/v1/attack-paths/{route_id}', { params: { path: { route_id: props.routeId }, query: { target: props.target } } }))
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return 'missing' as const
      throw err
    }
  },
  { watch: [() => props.routeId, () => props.target] },
)
const found = computed(() => {
  const d = detail.data.value
  return d && d !== 'missing' && d.id === props.routeId && d.target === props.target ? d : null
})
// A target past the route's list (an old link): the worst one instead.
watch(
  () => detail.data.value,
  (d) => {
    if (d === 'missing' && props.target > 1) emit('move', { target: 1, step: 1 })
  },
)
const notFound = computed(() => detail.data.value === 'missing' && props.target === 1)
const evaluation = useResource(() => unwrap(api.GET('/api/v1/attack-paths/evaluation')))
const behind = computed(() => {
  const e = evaluation.data.value
  return e?.behind && e.evaluated_at ? e.evaluated_at : null
})

const steps = computed<StepOut[]>(() => found.value?.steps ?? [])
const total = computed(() => steps.value.length)
const current = computed(() => Math.min(Math.max(props.step, 1), Math.max(total.value, 1)))
// A step past the chain (an old link): the nearest one, in the URL too.
watch([found, () => props.step], () => {
  if (found.value && current.value !== props.step) emit('move', { step: current.value })
})
const currentStep = computed(() => steps.value.find((s) => s.n === current.value) ?? null)

const name = (n: Pick<StepNode, 'uid' | 'kind' | 'name' | 'type' | 'resource_id'>) => nodeLabel(n, props.names).name
const title = computed(() => (found.value ? routeTitle(found.value, props.names) : 'Route'))
const chosen = computed(() => found.value?.targets.find((t) => t.seq === found.value!.target) ?? null)
const drawing = computed(() => routeDrawing(steps.value, props.accounts))
// The canvas's graph: the route's cards only, as the Security view draws them (card B).
const graph = computed<GraphState>(() => ({
  nodes: new Map(drawing.value.nodes.map((n): [string, MapNode] => [n.uid, { ...n, boundary: false, expanded: true, provider: null, region: null }])),
  edges: new Map(),
  groups: new Map(),
}))
const canvasRoute = computed(() => (found.value ? { drawing: drawing.value, current: current.value, title: title.value } : null))

// ---- The player (§4.4): opens paused; Play advances every 2.5 s and stops at the end.
const PLAY_MS = 2500
const playing = ref(false)
const ended = computed(() => total.value > 0 && current.value >= total.value)
let timer: number | undefined
function stop(): void {
  playing.value = false
  window.clearInterval(timer)
  timer = undefined
}
function go(n: number, keepPlaying = false): void {
  if (!keepPlaying) stop()
  const next = Math.min(Math.max(n, 1), total.value)
  if (next !== current.value) emit('move', { step: next })
}
function togglePlay(): void {
  if (playing.value) {
    stop()
    return
  }
  if (!total.value) return
  if (ended.value) go(1)
  playing.value = true
  timer = window.setInterval(() => {
    if (current.value >= total.value) stop()
    else go(current.value + 1, true)
  }, PLAY_MS)
}
// The last step stops the play (the button reads Replay).
watch(ended, (end) => {
  if (end) stop()
})
watch([() => props.routeId, () => props.target], stop)
onBeforeUnmount(stop)

function chooseTarget(event: Event): void {
  stop()
  emit('move', { target: Number((event.target as HTMLSelectElement).value), step: 1 })
}
/** Where leaving goes: the current step's resource, else the entry (§11.1). */
function leaveTo(): string | null {
  stop()
  return leaveFocus(currentStep.value, found.value?.entry ?? null)
}
function leave(): void {
  emit('leave', leaveTo())
}
// The View switch leaves through MapView, to the same place.
defineExpose({ leaveTo })

/** The player's and the step list's keys (§4.4). */
function onKey(event: KeyboardEvent): void {
  const keys: Record<string, () => void> = {
    ArrowLeft: () => go(current.value - 1),
    ArrowRight: () => go(current.value + 1),
    Home: () => go(1),
    End: () => go(total.value),
    ' ': togglePlay,
    Escape: leave,
  }
  const act = keys[event.key]
  if (!act || !found.value) return
  // Arrows and Space stay with a field (the target select).
  if (event.target instanceof HTMLSelectElement && event.key !== 'Escape') return
  event.preventDefault()
  act()
}

// A card on the canvas moves the player to the first step that ends there (§4.5).
function onCanvasSelect(sel: Selection | null): void {
  if (sel?.kind === 'node') go(stepAtCard(steps.value, sel.id))
}

// ---- The step list.
const crossed = computed(() => crossings(steps.value, props.accounts))
const announcement = computed(() => (currentStep.value ? stepAnnouncement(currentStep.value, total.value, name, crossed.value.get(currentStep.value.n) ?? null) : ''))
const level = (s: StepOut) => s.level as StepLevel
const stepTitle = (s: StepOut) => (isMove(s) ? moveWords(s).short : selfStepTitle(s, name(s.target)))
const stepPath = (s: StepOut) => (isMove(s) ? `${name(s.source)} → ${name(s.target)}` : name(s.target))
const resourceLink = (id: number) => ({ name: 'resources', query: { open: String(id) } })
const listRef = ref<HTMLElement | null>(null)
// The current item stays in view in the list as the player moves.
watch(current, () => {
  window.requestAnimationFrame(() => listRef.value?.querySelector('[aria-current="step"]')?.scrollIntoView({ block: 'nearest' }))
})
</script>

<template>
  <EmptyState v-if="notFound" icon="route" title="This route is not stored any more." text="It was fixed and later removed, or the link is from another install.">
    <RouterLink class="btn btn-secondary" :to="{ name: 'attack-paths' }">Back to Attack paths</RouterLink>
    <button type="button" class="btn btn-ghost" @click="emit('leave', null)">Leave route</button>
  </EmptyState>
  <template v-else>
    <section class="card player" aria-label="Route player" @keydown="onKey">
      <div class="player-title">
        <span class="eyebrow">Route</span>
        <span class="route-title" :title="title">{{ title }}</span>
        <span v-if="chosen" class="to">· to {{ name(chosen.target) }}</span>
      </div>
      <div class="controls">
        <button type="button" class="btn btn-secondary ctl" aria-label="First step" title="First step" :disabled="!found" :aria-disabled="current <= 1 ? 'true' : undefined" @click="go(1)"><AppIcon name="first" :size="16" /></button>
        <button type="button" class="btn btn-secondary ctl" aria-label="Previous step" title="Previous step" :disabled="!found" :aria-disabled="current <= 1 ? 'true' : undefined" @click="go(current - 1)"><AppIcon name="chevron" :size="16" class="back" /></button>
        <button type="button" class="btn btn-primary ctl play" :aria-label="playing ? 'Pause' : ended ? 'Replay the route' : 'Play the route'" :disabled="!found" @click="togglePlay">
          <AppIcon :name="playing ? 'pause' : 'play'" :size="16" />{{ playing ? 'Pause' : ended ? 'Replay' : 'Play' }}
        </button>
        <button type="button" class="btn btn-secondary ctl" aria-label="Next step" title="Next step" :disabled="!found" :aria-disabled="ended ? 'true' : undefined" @click="go(current + 1)"><AppIcon name="chevron" :size="16" /></button>
        <span class="count mono">Step <strong>{{ found ? current : '–' }}</strong> of {{ found ? total : '–' }}</span>
      </div>
      <span class="ends">
        <RouterLink class="btn btn-ghost" :to="{ name: 'attack-paths', query: { route: String(routeId), target: target > 1 ? String(target) : undefined } }">
          Details<span class="sr-only"> of this route</span>
        </RouterLink>
        <button type="button" class="btn btn-ghost leave" @click="leave"><AppIcon name="cross" :size="16" />Leave route</button>
      </span>
    </section>

    <AlertBanner v-if="detail.error.value" kind="fail">
      This route didn't load: {{ detail.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="detail.reload">Retry</button></template>
    </AlertBanner>
    <AlertBanner v-if="found?.resolved_on" kind="info">Fixed on {{ found.resolved_on }}. The steps are shown as last found.</AlertBanner>
    <AlertBanner v-if="behind" kind="info">Routes are behind the scans: they were worked out at {{ utc(behind) }}. They update after the next evaluation.</AlertBanner>

    <div class="attack">
      <section class="card canvas-card" :aria-label="`Attack Path view: ${title}`">
        <div v-if="!found" class="skeleton-map" aria-busy="true" aria-label="Loading the route">
          <div v-for="n in 4" :key="n" class="sk-node"></div>
        </div>
        <MapCanvas v-else :key="`${routeId}-${target}`" map="security" :graph="graph" :focus="null" :selection="null" :connection-name="names.connection" :route="canvasRoute" @select="onCanvasSelect" />
      </section>

      <aside ref="listRef" class="card steps" aria-labelledby="attack-steps" @keydown="onKey">
        <div class="steps-head">
          <h2 id="attack-steps" class="h2">Steps</h2>
          <label v-if="found && found.targets.length > 1" class="field target-field">
            <span class="lbl">Target</span>
            <select class="select" :value="found.target" @change="chooseTarget">
              <option v-for="t in found.targets" :key="t.seq" :value="t.seq">{{ name(t.target) }} · {{ SEVERITY_LABEL[t.severity] }}</option>
            </select>
          </label>
          <p v-else-if="chosen" class="cap">To {{ name(chosen.target) }}</p>
        </div>
        <div v-if="!found" class="loading" aria-busy="true"><div v-for="n in 4" :key="n" class="skeleton sk-step"></div></div>
        <ol v-else class="step-list">
          <li v-for="s in steps" :key="s.n" :aria-current="s.n === current ? 'step' : undefined" :class="{ current: s.n === current }">
            <button type="button" class="step-row" @click="go(s.n)">
              <span class="n mono" aria-hidden="true">{{ s.n }}</span>
              <span class="step-text">
                <span class="step-title"><span class="sr-only">Step {{ s.n }}: </span>{{ stepTitle(s) }}</span>
                <span class="step-path">{{ stepPath(s) }}</span>
                <span class="step-meta">
                  <span class="level" :title="LEVEL_MEANING[level(s)]">{{ LEVEL_LABEL[level(s)] }}</span>
                  <span v-if="crossed.get(s.n)" class="chip">into {{ crossed.get(s.n) }}</span>
                </span>
              </span>
            </button>
            <div v-if="s.n === current" class="step-body">
              <StepEvidence :step="s" />
              <RouterLink v-if="s.target.resource_id != null" class="open" :to="resourceLink(s.target.resource_id)" target="_blank">
                Open {{ name(s.target) }} in Resources<span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span>
              </RouterLink>
            </div>
          </li>
        </ol>
      </aside>
    </div>
    <p class="sr-only" role="status" aria-live="polite">{{ announcement }}</p>
  </template>
</template>

<style scoped>
/* The player takes the map toolbar's row (§11.5). */
.player {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-12) var(--s-16);
  padding: var(--s-12) var(--s-16);
}

.player-title {
  display: flex;
  align-items: baseline;
  gap: var(--s-8);
  min-width: 0;
  flex: 1 1 260px;
}

.eyebrow {
  flex: none;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-3);
}

.route-title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
  color: var(--text);
}

.to {
  flex: none;
  max-width: 40%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-2);
  font-size: 13px;
}

.controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6);
  min-width: 0;
}

.ctl {
  height: 32px;
  min-width: 32px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--s-6);
}

.back {
  transform: rotate(180deg);
}

/* At either end a step button does nothing, but keeps focus (a disabled button would drop it, and
   the player's keys with it). */
.ctl[aria-disabled='true'] {
  opacity: 0.5;
  cursor: default;
}

.count {
  margin-left: var(--s-8);
  font-size: 12.5px;
  color: var(--text-2);
  white-space: nowrap;
}

.count strong {
  color: var(--text);
}

.ends {
  display: inline-flex;
  flex-wrap: wrap;
  gap: var(--s-4);
}

.leave {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

@media (pointer: coarse) {
  .ctl,
  .leave {
    min-height: 44px;
    min-width: 44px;
  }
}

/* Canvas and a docked step list (>= 1200 px), the list over the canvas (900-1200), below (< 900). */
.attack {
  --map-h: clamp(600px, calc(100vh - 300px), 960px);

  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 380px;
  gap: var(--s-16);
}

.canvas-card {
  display: flex;
  flex-direction: column;
  height: var(--map-h);
  padding: 0;
  overflow: hidden;
}

.steps {
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
  padding: var(--s-16);
  max-height: var(--map-h);
  overflow-y: auto;
}

@media (max-width: 1199px) {
  .attack {
    grid-template-columns: minmax(0, 1fr);
  }

  .steps {
    position: absolute;
    top: 0;
    right: 0;
    width: 380px;
    max-height: 100%;
    box-shadow: var(--shadow-sheet);
    z-index: 6;
  }
}

@media (max-width: 899px) {
  .canvas-card {
    height: 360px;
  }

  .canvas-card :deep(.region) {
    min-height: 0;
  }

  .steps {
    position: static;
    width: auto;
    max-height: none;
    box-shadow: none;
  }

  /* Title on its own line, the controls and Leave route under it (§4.7). */
  .player-title {
    flex-basis: 100%;
  }
}

.steps-head {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--s-8) var(--s-12);
}

.steps-head .h2,
.steps-head .cap {
  margin: 0;
}

.cap {
  font-size: 12.5px;
  color: var(--text-2);
}

.target-field {
  min-width: 0;
  max-width: 100%;
}

.target-field .select {
  max-width: 100%;
}

.step-list {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  margin: 0;
  padding: 0;
  list-style: none;
}

.step-list li {
  border-left: 2px solid transparent;
  border-radius: var(--r-tile);
}

/* The current step: the accent wash and bar (interaction), as the route page's chosen target. */
.step-list li.current {
  background: var(--accent-wash);
  border-left-color: var(--accent);
}

.step-row {
  display: flex;
  align-items: flex-start;
  gap: var(--s-10);
  width: 100%;
  min-height: 44px;
  padding: var(--s-8) var(--s-10);
  border: 0;
  border-radius: var(--r-tile);
  background: none;
  color: var(--text);
  text-align: left;
  cursor: pointer;
}

.step-row:hover {
  background: var(--surface-active);
}

.n {
  flex: none;
  display: inline-grid;
  place-items: center;
  width: 22px;
  height: 22px;
  border: 1px solid var(--graph-edge);
  border-radius: 50%;
  background: var(--surface);
  font-size: 11px;
}

li.current .n {
  border: 2px solid var(--accent);
  font-weight: 600;
}

.step-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.step-title {
  font-size: 13px;
  font-weight: 500;
  overflow-wrap: anywhere;
}

.step-path {
  font-size: 12px;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

.step-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6);
}

/* A step's level: the word only, small caps (the route page's). */
.level {
  font-size: 11px;
  font-weight: 600;
  font-variant: all-small-caps;
  letter-spacing: 0.04em;
  color: var(--text-2);
}

.chip {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
}

.step-body {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding: 0 var(--s-10) var(--s-10) calc(var(--s-10) + 22px + var(--s-10));
}

.open {
  font-size: 12.5px;
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.sk-step {
  height: 52px;
  border-radius: var(--r-tile);
}

.skeleton-map {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-wrap: wrap;
  gap: 56px;
  flex: 1;
  padding: var(--s-48);
  background-color: var(--graph-canvas);
  background-image: radial-gradient(circle, var(--graph-dot) 1px, transparent 1.2px);
  background-size: 22px 22px;
}

.sk-node {
  width: 208px;
  height: 64px;
  border-radius: var(--r-tile);
  background: var(--surface-raised);
}
</style>
