<script setup lang="ts">
/**
 * One attack route (spec W6 §3 and its R2 delta §10): why it has its severity and confidence,
 * its worst targets, and the chosen target's steps as a vertical chain in walk order. Each link
 * says how sure Argus is of it and opens its evidence and fix; a foothold or a login is its own
 * step on the resource it stands on. A resource step opens its detail sheet in place. Stored
 * steps only: nothing here is walked. Cloud names are text, never markup.
 */
import { computed, nextTick, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useResource } from '@/composables/useResource'
import { originLabel } from '../labels'
import CountPill from '../map/CountPill.vue'
import { factLines, factSub, pillCount, worstOf } from '../map/mapFacts'
import ResourceSheet from '../ResourceSheet.vue'
import { LEVEL_LABEL, LEVEL_MEANING, LIKELIHOOD_LINE, confidenceLine, type StepLevel } from './routeClass'
import RouteClassBadge from './RouteClassBadge.vue'
import StepEvidence from './StepEvidence.vue'
import { parseTarget } from './routeFilters'
import {
  accountName,
  chainItems,
  moveWords,
  nodeLabel,
  routeTitle,
  selfStepTitle,
  type Names,
  type StepNode,
  type StepOut,
} from './routeWords'

const props = defineProps<{ routeId: number; names: Names }>()
const emit = defineEmits<{ loaded: [title: string | null] }>()

const route = useRoute()
const router = useRouter()
const target = computed(() => parseTarget(route.query))

const detail = useResource(
  async () => {
    try {
      return await unwrap(api.GET('/api/v1/attack-paths/{route_id}', { params: { path: { route_id: props.routeId }, query: { target: target.value } } }))
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return 'missing' as const
      throw err
    }
  },
  { watch: [() => props.routeId, () => target.value] },
)
const found = computed(() => {
  const d = detail.data.value
  return d && d !== 'missing' && d.id === props.routeId ? d : null
})
// A target past the route's list (an old link): the worst one instead (§10.9).
watch(
  () => detail.data.value,
  (d) => {
    if (d === 'missing' && target.value > 1) void router.replace({ query: { ...route.query, target: undefined } })
  },
)
const notFound = computed(() => detail.data.value === 'missing' && target.value === 1)

const title = computed(() => (found.value ? routeTitle(found.value, props.names) : null))
watch(title, (t) => emit('loaded', t), { immediate: true })
// The heading takes focus when a route opens (the router's focus runs before it has loaded).
let focused: number | null = null
watch(found, (r) => {
  if (!r || focused === r.id) return
  focused = r.id
  void nextTick(() => document.getElementById('route-title')?.focus())
})

/** attack.mitre.org/techniques/T1078/004/ for T1078.004. */
const techniqueUrl = computed(() => {
  const t = found.value?.technique
  return t && /^T\d{4}(\.\d{3})?$/.test(t) ? `https://attack.mitre.org/techniques/${t.replace('.', '/')}/` : null
})

const label = (n: Pick<StepNode, 'uid' | 'kind' | 'name' | 'type' | 'resource_id'>) => nodeLabel(n, props.names)
const entryAccount = computed(() => (found.value ? props.names.connection(found.value.connection_id) : ''))
const crossed = computed(() => (found.value ? found.value.crossed_connection_ids.filter((id) => id !== found.value!.connection_id).map(props.names.connection) : []))
const chosen = computed(() => found.value?.targets.find((t) => t.seq === found.value!.target) ?? null)
const items = computed(() => (found.value ? chainItems(found.value.steps) : []))

function chooseTarget(seq: number): void {
  void router.replace({ query: { ...route.query, target: seq > 1 ? String(seq) : undefined } })
}

/** "in Shared" for a step outside the entry's account. */
function otherAccount(node: StepNode): string | null {
  const r = found.value
  if (!r || node.kind === 'internet') return null
  if (node.connection_id != null && node.connection_id === r.connection_id) return null
  const name = accountName(node, props.names)
  return name && name !== entryAccount.value ? name : null
}

// "Evidence and fix": one step's evidence at a time, under its link.
const openStep = ref<number | null>(null)
watch([() => props.routeId, target], () => (openStep.value = null))
const level = (s: StepOut) => s.level as StepLevel

// A resource step opens its sheet in place.
const sheet = ref<{ id: number; name: string } | null>(null)
type RouteDetailOut = Schemas['RouteDetail']
const kindLabel = (r: RouteDetailOut) => r.kind_name ?? r.kind
// The Map's Attack Path view at this target, step 1 (W6 §11.1).
const mapLink = computed(() => ({ name: 'map', query: { mode: 'attack', route: String(props.routeId), target: target.value > 1 ? String(target.value) : undefined } }))
</script>

<template>
  <EmptyState v-if="notFound" icon="route" title="Attack path not found.">
    <slot name="back" />
  </EmptyState>
  <AlertBanner v-else-if="detail.error.value" kind="fail">
    This attack path didn't load: {{ detail.error.value }}
    <template #action><button type="button" class="btn btn-secondary btn-sm" @click="detail.reload">Retry</button></template>
  </AlertBanner>
  <div v-else-if="!found" class="loading" aria-busy="true" aria-label="Loading the attack path">
    <div class="card skeleton sk-160"></div>
    <div class="card skeleton sk-120"></div>
    <div class="card skeleton sk-160"></div>
  </div>
  <template v-else>
    <header class="card summary detail-head">
      <div class="detail-title">
        <h1 id="route-title" tabindex="-1" data-page-title>{{ title }}</h1>
        <span class="detail-badges">
          <SeverityTag :severity="found.severity" />
          <RouteClassBadge :cls="found.worst_class" />
          <StatusBadge v-if="found.resolved_on" status="resolved" :label="`Fixed ${found.resolved_on}`" />
          <StatusBadge v-else-if="found.state === 'reopened'" status="reopened" />
        </span>
        <RouterLink class="btn btn-secondary show-on-map" :to="mapLink">
          <AppIcon name="graph" :size="16" />Show on map
        </RouterLink>
      </div>
      <dl class="detail-facts">
        <div>
          <dt>Kind</dt>
          <dd :class="{ mono: !found.kind_name }">{{ kindLabel(found) }}</dd>
        </div>
        <div v-if="found.category">
          <dt>Category</dt>
          <dd>{{ found.category }}</dd>
        </div>
        <div v-if="found.technique">
          <dt>Technique</dt>
          <dd>
            <a v-if="techniqueUrl" :href="techniqueUrl" target="_blank" rel="noopener noreferrer" class="mono">{{ found.technique }}<span class="sr-only"> (MITRE ATT&amp;CK, opens in a new tab)</span></a>
            <span v-else class="mono">{{ found.technique }}</span>
          </dd>
        </div>
        <div>
          <dt>Gets in at</dt>
          <dd>{{ label(found.entry).name }} <span class="muted">· {{ label(found.entry).type }} · {{ entryAccount }}</span></dd>
        </div>
        <div>
          <dt>Accounts</dt>
          <dd>{{ entryAccount }}<template v-if="crossed.length">, crosses {{ crossed.join(', ') }}</template></dd>
        </div>
        <div>
          <dt>First seen</dt>
          <dd class="mono">{{ found.first_seen }}</dd>
        </div>
        <div v-if="found.resolved_on">
          <dt>Fixed on</dt>
          <dd class="mono">{{ found.resolved_on }}</dd>
        </div>
        <div v-else>
          <dt>Last seen</dt>
          <dd class="mono">{{ found.last_seen }}</dd>
        </div>
      </dl>
      <p v-if="chosen" class="why">{{ LIKELIHOOD_LINE[chosen.likelihood] }}</p>
      <p class="why">{{ confidenceLine(found.worst_class) }}</p>
      <p v-if="found.description" class="body">{{ found.description }}</p>
      <p v-else-if="!found.kind_name" class="body">This release has no file for kind <span class="mono">{{ found.kind }}</span> any more: its description is not available.</p>
    </header>

    <section class="card targets" aria-labelledby="route-targets">
      <span id="route-targets" class="eyebrow">Targets</span>
      <p v-if="found.targets.length === 1 && chosen" class="body">
        Target: {{ label(chosen.target).name }}<template v-if="accountName(chosen.target, names)"> in {{ accountName(chosen.target, names) }}</template>
      </p>
      <ul v-else class="target-list">
        <li v-for="t in found.targets" :key="t.seq">
          <button type="button" class="target" :aria-pressed="t.seq === found.target" @click="chooseTarget(t.seq)">
            <span class="t-main">
              <span class="t-name">{{ label(t.target).name }}</span>
              <span class="t-sub">{{ label(t.target).type }}<template v-if="accountName(t.target, names)"> · {{ accountName(t.target, names) }}</template></span>
            </span>
            <span class="t-facts">
              <SeverityTag :severity="t.severity" compact />
              <RouteClassBadge :cls="t.cls" />
              <span class="mono steps-n">{{ t.steps }} {{ t.steps === 1 ? 'step' : 'steps' }}</span>
            </span>
          </button>
        </li>
      </ul>
      <p v-if="found.target_count > found.listed_count" class="cap">
        {{ (found.target_count - found.listed_count).toLocaleString('en-US') }} more {{ found.target_count - found.listed_count === 1 ? 'target' : 'targets' }}, not listed. Argus keeps the {{ found.listed_count }} worst. The route stays open until no target remains.
      </p>
    </section>

    <section class="card steps" aria-labelledby="route-steps">
      <h2 id="route-steps" class="h2">Steps<template v-if="chosen"> to {{ label(chosen.target).name }}</template></h2>
      <AlertBanner v-if="found.resolved_on" kind="info">This route was fixed on {{ found.resolved_on }}. Its steps are shown as last found.</AlertBanner>
      <ol class="chain">
        <li v-for="item in items" :key="item.key" :class="`item item-${item.kind}`">
          <!-- A resource, or a pseudo-node (the internet, an administrator, every store of a service). -->
          <div v-if="item.kind === 'node'" class="node">
            <span class="type mono">{{ label(item.node).type }}</span>
            <span class="name-line">
              <button v-if="item.node.resource_id != null" type="button" class="name link-btn" :title="item.node.uid" @click="sheet = { id: item.node.resource_id!, name: label(item.node).name }">{{ label(item.node).name }}</button>
              <span v-else class="name" :title="item.node.uid">{{ label(item.node).name }}</span>
              <span v-if="otherAccount(item.node)" class="chip acct">in {{ otherAccount(item.node) }}</span>
              <span v-if="item.node.deleted_on" class="chip removed">Removed on {{ item.node.deleted_on }}</span>
            </span>
            <span v-if="item.node.facts" class="facts" :title="factLines(item.node.facts, names.connection(item.node.connection_id ?? 0)).join('\n')">
              <CountPill v-if="pillCount(item.node.facts) && worstOf(item.node.facts)" :count="pillCount(item.node.facts)!" :severity="worstOf(item.node.facts)!" base="var(--surface-raised)" />
              <span class="fact-words">{{ factSub(item.node.facts).join(' · ') || 'No open misconfigurations' }}</span>
            </span>
          </div>

          <!-- A walk-made step on the resource above: a foothold, or a login to a database. -->
          <div v-else-if="item.kind === 'self'" class="self">
            <span class="n mono" aria-hidden="true">{{ item.step.n }}</span>
            <div class="self-body">
              <span class="self-title"><span class="sr-only">Step {{ item.step.n }}: </span>{{ selfStepTitle(item.step, label(item.step.target).name) }}</span>
              <span class="level" :title="LEVEL_MEANING[level(item.step)]">{{ LEVEL_LABEL[level(item.step)] }}</span>
              <StepEvidence :step="item.step" />
            </div>
          </div>

          <!-- A move from the resource above to the one below. -->
          <div v-else class="link">
            <span class="n mono" aria-hidden="true">{{ item.step.n }}</span>
            <div class="link-body">
              <span class="link-line">
                <span class="move"><span class="sr-only">Step {{ item.step.n }}: </span>{{ moveWords(item.step).short }}</span>
                <span class="chip" :title="item.step.origin">{{ originLabel(item.step.origin) }}</span>
                <span class="level" :title="LEVEL_MEANING[level(item.step)]">{{ LEVEL_LABEL[level(item.step)] }}</span>
                <span v-if="item.step.day" class="mono small">{{ item.step.day }}</span>
                <button
                  type="button"
                  class="disclosure"
                  :aria-expanded="openStep === item.step.n"
                  :aria-controls="`evidence-${item.step.n}`"
                  @click="openStep = openStep === item.step.n ? null : item.step.n"
                >
                  Evidence and fix
                </button>
              </span>
              <div v-if="openStep === item.step.n" :id="`evidence-${item.step.n}`" role="region" :aria-label="`Evidence and fix for step ${item.step.n}`">
                <StepEvidence :step="item.step" />
              </div>
            </div>
          </div>
        </li>
      </ol>
    </section>

    <section class="card fix" aria-labelledby="route-fix">
      <h2 id="route-fix" class="h2">How to fix</h2>
      <p v-if="found.remediation" class="body">{{ found.remediation }}</p>
      <p class="body">Breaking any one link above ends the route to this target. The route is fixed when no target remains.</p>
    </section>
  </template>

  <ResourceSheet v-if="sheet" :resource-id="sheet.id" :fallback-title="sheet.name" :connection-name="names.connection" @close="sheet = null" />
</template>

<style scoped>
/* The Map's Attack Path view (W6 §11.1): on the title row's right. */
.show-on-map {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
}

.summary,
.targets,
.steps,
.fix {
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
  padding: var(--s-20);
}

.summary p,
.targets p,
.fix p,
.steps .h2,
.fix .h2 {
  margin: 0;
}

.why {
  color: var(--text-2);
  font-size: 13px;
}

.muted {
  color: var(--text-2);
}

.body {
  font-size: 13px;
  line-height: 1.55;
  max-width: 80ch;
}

.eyebrow {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-3);
}

/* Targets: a list of buttons; the chosen one has the accent wash and bar (interaction). */
.target-list {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  margin: 0;
  padding: 0;
  list-style: none;
}

.target {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-8) var(--s-12);
  width: 100%;
  min-height: 44px;
  padding: var(--s-8) var(--s-12);
  border: 1px solid var(--border);
  border-left: 2px solid transparent;
  border-radius: var(--r-tile);
  background: var(--surface-raised);
  color: var(--text);
  text-align: left;
  cursor: pointer;
}

.target:hover {
  background: var(--surface-active);
}

.target[aria-pressed='true'] {
  background: var(--accent-wash);
  border-left-color: var(--accent);
}

.t-main {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.t-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--link);
  overflow-wrap: anywhere;
}

.t-sub,
.small {
  font-size: 12px;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

.t-facts {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-8);
}

.steps-n {
  font-size: 12px;
  color: var(--text-2);
}

/* The chain, vertical at every width (§10.4): resources, with each step between them. */
.chain {
  display: flex;
  flex-direction: column;
  margin: 0;
  padding: 0;
  list-style: none;
}

.node {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  padding: var(--s-12);
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: var(--r-tile);
  min-width: 0;
}

.type {
  font-size: 11px;
  color: var(--text-3);
}

.name-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6) var(--s-8);
  min-width: 0;
}

.name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  overflow-wrap: anywhere;
}

.link-btn {
  padding: 0;
  border: 0;
  background: none;
  text-align: left;
  cursor: pointer;
  text-decoration: underline;
  text-decoration-color: var(--border-control);
  text-underline-offset: 3px;
}

.link-btn:hover {
  color: var(--link);
  text-decoration-color: currentcolor;
}

.acct,
.removed {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
}

.facts {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6);
}

.fact-words {
  font-size: 12px;
  color: var(--text-2);
}

/* A step between two resources: its number on the chain's rule, then its words. */
.link,
.self {
  display: flex;
  gap: var(--s-12);
  padding: var(--s-8) 0 var(--s-8) var(--s-12);
  margin-left: var(--s-12);
  border-left: 2px solid var(--graph-edge);
}

/* A foothold or a login is an assumption, not a line: a dashed rule. */
.self {
  border-left-style: dashed;
  border-left-color: var(--text-3);
}

.n {
  flex: none;
  display: inline-grid;
  place-items: center;
  width: 22px;
  height: 22px;
  margin-left: calc(-1 * var(--s-12) - 13px);
  border: 1px solid var(--graph-edge);
  border-radius: 50%;
  background: var(--surface);
  color: var(--text);
  font-size: 11px;
}

.link-body,
.self-body {
  display: flex;
  flex-direction: column;
  gap: var(--s-6);
  min-width: 0;
  flex: 1;
}

.link-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6) var(--s-8);
}

.move,
.self-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  overflow-wrap: anywhere;
}

/* A step's level: the word only, small caps, so it is never read as the route's class badge. */
.level {
  font-size: 11px;
  font-weight: 600;
  font-variant: all-small-caps;
  letter-spacing: 0.04em;
  color: var(--text-2);
}

.disclosure {
  min-height: 24px;
  padding: 0;
  border: 0;
  background: none;
  color: var(--link);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
}

.disclosure:hover {
  color: var(--link-hover);
  text-decoration: underline;
}

</style>
