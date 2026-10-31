<script setup lang="ts">
/**
 * One attack path (docs/ui/screens.md, E12, Path detail): why it has its severity and its
 * confidence, its steps from left to right with what each tool says about every one
 * (design-system.md, Step chain), and for each link its evidence (how sure, why, where from,
 * when seen) and how to break it. A resource step opens its detail sheet in place.
 */
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { originLabel } from '../labels'
import ResourceSheet from '../ResourceSheet.vue'
import DoorEvidence from '../map/DoorEvidence.vue'
import { doorOfEdge, doorWhy } from '../map/doorWhy'
import { nodeName, worstOf, type MapNode } from '../map/mapGraph'
import { confidenceLine } from './confidence'
import ConfidenceBadge from './ConfidenceBadge.vue'
import { factsOf, imdsV1, moveWords, stepLabel, type Move } from './pathWords'
import { breakLink, severityLine } from './pathText'

const props = defineProps<{ pathId: number; connectionName: (id: number) => string }>()
const emit = defineEmits<{ loaded: [path: Schemas['PathDetail'] | null] }>()

const detail = useResource(
  async () => {
    try {
      return await unwrap(api.GET('/api/v1/attack-paths/{path_id}', { params: { path: { path_id: props.pathId } } }))
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return 'missing' as const
      throw err
    }
  },
  { watch: [() => props.pathId] },
)
const path = computed(() => {
  const d = detail.data.value
  return d && d !== 'missing' && d.id === props.pathId ? d : null
})
const notFound = computed(() => detail.data.value === 'missing')
watch(path, (p) => emit('loaded', p), { immediate: true })

const line = computed(() => (path.value ? severityLine(path.value) : null))
const sureLine = computed(() => confidenceLine(path.value?.confidence))
/** attack.mitre.org/techniques/T1078/004/ for T1078.004. */
const techniqueUrl = computed(() => {
  const t = path.value?.rule?.technique
  return t && /^T\d{4}(\.\d{3})?$/.test(t) ? `https://attack.mitre.org/techniques/${t.replace('.', '/')}/` : null
})

type PathEdge = Schemas['PathEdge']
interface Step {
  node: MapNode
  label: { type: string; name: string }
  edge: PathEdge | null // the link to the next step, with its evidence
  move: Move | null // that link in words
  reversed: boolean // the edge points back (an instance MEMBER_OF its security group)
  imdsV1: boolean // the entry instance lets a foothold read its role's credentials
}
const steps = computed<Step[]>(() => {
  const p = path.value
  if (!p) return []
  return p.nodes.map((node, i) => {
    const edge = i < p.nodes.length - 1 ? (p.edges[i] ?? null) : null
    const inbound = i > 0 ? (p.edges[i - 1] ?? null) : null
    return {
      node,
      label: stepLabel(node, inbound),
      edge,
      move: edge ? moveWords(edge) : null,
      reversed: !!edge && edge.source_uid !== node.uid,
      imdsV1: i === 1 && imdsV1(inbound),
    }
  })
})

// "Evidence and fix": the open link's evidence shows under the chain, full width.
const openLink = ref<number | null>(null)
watch(() => props.pathId, () => (openLink.value = null))
const opened = computed(() => {
  const i = openLink.value
  const step = i == null ? null : steps.value[i]
  if (!step?.edge || !step.move) return null
  // The step in from the internet: the door's reach line and evidence, as the front doors show them.
  const door = step.edge.source_uid === 'internet' ? doorOfEdge(step.edge) : null
  return {
    index: i!,
    edge: step.edge,
    move: step.move,
    door,
    doorLine: door ? doorWhy(door) : null,
    facts: factsOf(step.edge),
    sentence: breakLink(step.edge),
  }
})

// A resource step opens its sheet in place.
const sheet = ref<{ id: number; name: string } | null>(null)
const mapLink = computed(() => (path.value ? { name: 'resource-map', query: { focus: path.value.entry_uid, connection: String(path.value.connection_id), depth: '3', path: String(path.value.id) } } : null))
</script>

<template>
  <EmptyState v-if="notFound" icon="route" title="Attack path not found.">
    <slot name="back" />
  </EmptyState>
  <AlertBanner v-else-if="detail.error.value" kind="fail">
    This attack path didn't load: {{ detail.error.value }}
    <template #action><button type="button" class="btn btn-secondary btn-sm" @click="detail.reload">Retry</button></template>
  </AlertBanner>
  <div v-else-if="!path" class="loading" aria-busy="true" aria-label="Loading the attack path">
    <div class="card skeleton sk-160"></div>
    <div class="card chain-skeleton">
      <template v-for="n in 4" :key="n"><div class="skeleton sk-step"></div><div v-if="n < 4" class="sk-link"></div></template>
    </div>
    <div class="card skeleton sk-120"></div>
  </div>
  <template v-else>
    <!-- The detail page's header card (design-system.md, Page header → detail page). -->
    <header class="card summary detail-head">
      <div class="detail-title">
        <h1 id="path-title" tabindex="-1" data-page-title>{{ path.rule?.name ?? path.rule_name ?? path.rule_id }}</h1>
        <span class="detail-badges">
          <SeverityTag :severity="path.severity" />
          <ConfidenceBadge v-if="path.confidence" :level="path.confidence" />
          <StatusBadge v-if="path.resolved_on" status="resolved" :label="`Resolved ${path.resolved_on}`" />
        </span>
      </div>
      <dl class="detail-facts">
        <div>
          <dt><span aria-hidden="true">📂 </span>Category</dt>
          <dd>{{ path.category }}</dd>
        </div>
        <div v-if="path.rule?.technique">
          <dt><span aria-hidden="true">🎯 </span>Technique</dt>
          <dd>
            <a v-if="techniqueUrl" :href="techniqueUrl" target="_blank" rel="noopener noreferrer" class="mono">{{ path.rule.technique }}<span class="sr-only"> (MITRE ATT&amp;CK, opens in a new tab)</span></a>
            <span v-else class="mono">{{ path.rule.technique }}</span>
          </dd>
        </div>
        <div>
          <dt><span aria-hidden="true">🖥 </span>Connection</dt>
          <dd>{{ path.connection }}</dd>
        </div>
        <div>
          <dt><span aria-hidden="true">📅 </span>First seen</dt>
          <dd class="mono">{{ path.first_seen }}</dd>
        </div>
        <div>
          <dt><span aria-hidden="true">📅 </span>Last seen</dt>
          <dd class="mono">{{ path.last_seen }}</dd>
        </div>
      </dl>
      <p v-if="line" class="why">{{ line }}</p>
      <p v-if="sureLine && path.confidence" class="why">Confidence: {{ sureLine }}</p>
      <p v-if="path.rule?.description" class="body">{{ path.rule.description }}</p>
      <p v-else-if="!path.rule" class="body">This release has no file for rule <span class="mono">{{ path.rule_id }}</span> any more: its description is not available.</p>
      <div>
        <RouterLink v-if="mapLink" class="btn btn-secondary" :to="mapLink"><AppIcon name="graph" :size="16" />Open in map</RouterLink>
      </div>
    </header>

    <section class="card steps" aria-labelledby="path-steps">
      <h2 id="path-steps" class="h2">Steps</h2>
      <ol class="chain">
        <li v-for="(step, i) in steps" :key="`${i}-${step.node.uid}`" class="step-item">
          <div class="step">
            <span class="type mono">{{ step.label.type }}</span>
            <button v-if="step.node.resource_id != null" type="button" class="name link-btn" :title="step.node.uid" @click="sheet = { id: step.node.resource_id!, name: nodeName(step.node) }">
              {{ step.label.name }}
            </button>
            <span v-else class="name" :title="step.node.uid">{{ step.label.name }}</span>
            <span v-if="worstOf(step.node).worst" class="badge">
              <SeverityTag :severity="worstOf(step.node).worst!" compact /><span class="mono">{{ worstOf(step.node).open }}</span>
            </span>
            <span v-if="Object.keys(step.node.findings).length" class="tools">
              <span v-for="(f, tool) in step.node.findings" :key="tool" class="tool"><ToolChip :tool="String(tool)" /><span class="mono">{{ f.open }}</span></span>
            </span>
            <span v-else class="none">No open findings</span>
            <span v-if="step.imdsV1" class="warn-line"><AppIcon name="warning" :size="14" />IMDSv1: a foothold here reads its role's credentials</span>
          </div>
          <div v-if="step.edge && step.move" class="link">
            <span class="move" :title="step.move.short">{{ step.move.short }}</span>
            <span class="arrow" aria-hidden="true">{{ step.reversed ? '←' : '→' }}</span>
            <span v-if="step.reversed" class="sr-only">(points back to this step)</span>
            <span class="chip" :title="step.edge.origin">{{ originLabel(step.edge.origin) }}</span>
            <ConfidenceBadge :level="step.edge.confidence" :why="step.edge.confidence_why" />
            <button
              type="button"
              class="disclosure"
              :aria-expanded="openLink === i"
              aria-controls="break-link"
              @click="openLink = openLink === i ? null : i"
            >
              Evidence and fix
            </button>
          </div>
        </li>
      </ol>
      <div v-if="opened" id="break-link" class="break" role="region" :aria-label="`Evidence and fix for the link: ${opened.move.short}`">
        <p class="sentence">{{ opened.move.sentence }}</p>
        <p class="body evidence">
          <ConfidenceBadge :level="opened.edge.confidence" :why="opened.edge.confidence_why" />
          <span>{{ opened.edge.confidence_why }}</span>
        </p>
        <template v-if="opened.door">
          <p v-if="opened.doorLine" class="body">{{ opened.doorLine }}</p>
          <DoorEvidence v-if="opened.door.network.length || opened.door.state" :network="opened.door.network" :state="opened.door.state" />
        </template>
        <dl class="attrs">
          <div><dt class="lbl">Seen</dt><dd class="mono">{{ opened.edge.first_seen }} to {{ opened.edge.last_seen }}</dd></div>
          <div v-for="f in opened.facts" :key="f.label">
            <dt class="lbl">{{ f.label }}</dt>
            <dd :class="{ mono: f.mono }" :title="f.title">{{ f.value }}</dd>
          </div>
        </dl>
        <p class="body"><strong>Break this link:</strong> {{ opened.sentence }}</p>
        <!-- The codes behind the words, for whoever checks a rule (2026-10-31 review). -->
        <details class="tech">
          <summary>Technical details</summary>
          <dl class="attrs">
            <div><dt class="lbl">Link type</dt><dd class="mono">{{ opened.edge.type }}</dd></div>
            <div><dt class="lbl">Source</dt><dd class="mono">{{ opened.edge.source }}</dd></div>
          </dl>
        </details>
      </div>
    </section>

    <section class="card fix" aria-labelledby="path-fix">
      <h2 id="path-fix" class="h2">How to fix</h2>
      <p v-if="path.rule?.remediation" class="body">{{ path.rule.remediation }}</p>
      <p class="body">Breaking any one link above ends this path.</p>
    </section>
  </template>

  <ResourceSheet v-if="sheet" :resource-id="sheet.id" :fallback-title="sheet.name" :connection-name="connectionName" @close="sheet = null" />
</template>

<style scoped>
.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
}

.chain-skeleton {
  display: flex;
  align-items: center;
  padding: var(--s-20);
  overflow: hidden;
}

.sk-step {
  flex: 0 0 200px;
  height: 120px;
}

.sk-link {
  flex: 0 0 120px;
  height: 2px;
  background: var(--surface-raised);
}

.summary,
.steps,
.fix {
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
  padding: var(--s-20);
}

.summary p,
.fix p,
.steps .h2,
.fix .h2 {
  margin: 0;
}

.why {
  color: var(--text-2);
  font-size: 13px;
}

.evidence {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-8);
}

.body {
  font-size: 13px;
  line-height: 1.55;
  max-width: 80ch;
}

.chain {
  display: flex;
  margin: 0;
  padding: 0 0 var(--s-8);
  list-style: none;
  overflow-x: auto;
}

/* The steps share the row (168 to 220 px each), so a chain fits the card before it scrolls. */
.step-item {
  display: flex;
  align-items: center;
  flex: 1 1 auto;
  min-width: 0;
}

.step-item:last-child {
  flex-grow: 0;
}

.step {
  display: flex;
  flex-direction: column;
  gap: var(--s-6);
  flex: 1 1 200px;
  min-width: 168px;
  max-width: 220px;
  min-height: 120px;
  padding: var(--s-12);
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: var(--r-tile);
}

.type {
  font-size: 11px;
  color: var(--text-3);
}

.name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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

.badge,
.tools,
.tool {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6);
}

.tools {
  gap: var(--s-8);
}

.none {
  font-size: 12px;
  color: var(--text-3);
}

.link {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--s-4);
  width: 120px;
  padding: 0 var(--s-6);
  text-align: center;
}

/* The move: plain words, at most three lines on the link, the whole phrase in the tooltip. */
.move {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
  line-clamp: 3;
  overflow: hidden;
  font-size: 12px;
  font-weight: 500;
  line-height: 1.35;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

.warn-line {
  display: inline-flex;
  align-items: flex-start;
  gap: var(--s-4);
  font-size: 12px;
  font-weight: 500;
  color: var(--status-warn);
}

.warn-line :deep(svg) {
  flex: none;
  margin-top: 1px;
}

.sentence {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}

.tech summary {
  cursor: pointer;
  font-size: 12px;
  color: var(--text-3);
}

.tech summary:hover {
  color: var(--link);
}

.tech .attrs {
  margin-top: var(--s-8);
}

.arrow {
  font-size: 18px;
  line-height: 1;
  color: var(--graph-edge);
}

.disclosure {
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

.break {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding: var(--s-12) var(--s-14);
  background: var(--surface-sunken);
  border-radius: var(--r-tile);
}

.break p {
  margin: 0;
}

.attrs {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: var(--s-8) var(--s-16);
  font-size: 12px;
}

.attrs dd {
  margin: 2px 0 0;
  overflow-wrap: anywhere;
}

/* Under 900 px the chain turns vertical: each link between two steps, a downward arrow. */
@media (max-width: 899px) {
  .chain,
  .step-item {
    flex-direction: column;
    align-items: stretch;
  }

  .step {
    width: auto;
    max-width: none;
  }

  .link {
    flex-direction: row;
    flex-wrap: wrap;
    justify-content: center;
    width: auto;
    padding: var(--s-8) 0;
  }

  /* Beside the downward arrow, one line, never cut. */
  .move {
    display: block;
    -webkit-line-clamp: unset;
    line-clamp: unset;
  }

  .arrow {
    transform: rotate(90deg);
  }
}
</style>
