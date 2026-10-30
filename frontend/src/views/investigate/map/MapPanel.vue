<script setup lang="ts">
/**
 * The Resource map's docked panel (docs/ui/screens.md, E11, Resource panel): what each tool says
 * about the selected resource (ResourceDetail, the same body as the Resources sheet), a group's
 * members to add, or one connection with its origins. Not modal: the map stays usable beside it.
 * The page frames it (docked, overlaid, or as the detail sheet on a phone).
 */
import { computed, ref, watch } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import { useResource } from '@/composables/useResource'
import { originLabel, regionLabel } from '../labels'
import ResourceDetail from '../ResourceDetail.vue'
import type { DoorInterface } from './doorEvidence'
import DoorEvidence from './DoorEvidence.vue'
import type { FlowChip } from './flowGraph'
import { boundaryLabel, drawnEdges, nodeName, worstOf, type GraphState, type MapEdge, type MapNode, type Selection } from './mapGraph'
import { typeDisc, typeLabel } from './mapLanes'

const props = defineProps<{
  graph: GraphState
  selection: Selection | null
  asOf: string | null
  full: boolean // the map holds 500 nodes: nothing more can be added
  connectionName: (id: number) => string
  // The connection the map walks: a group's members are read in it.
  connectionId: number | null
  // Flow mode (ADR-0036): what each node carries. A flow is drawn whole: no Expand, and
  // "Explore around" opens a node's neighbourhood.
  flowChips?: ReadonlyMap<string, FlowChip[]> | null
  // Flow mode: the chain from the internet to the selected node, each step with the role a
  // USES step goes through (screens.md, E11, Path from the internet).
  flowPath?: { node: MapNode; via: string | null }[] | null
  // Shown as the sheet on a phone: the sheet has its own title and close button.
  framed?: boolean
}>()
const emit = defineEmits<{
  close: []
  expand: [uid: string]
  focusHere: [uid: string]
  add: [member: { node: MapNode; edge: MapEdge }]
  select: [selection: Selection]
}>()

const FULL = 'Showing 500 resources, the most this map draws. Turn off a layer or lower the depth to see the rest.'
const node = computed(() => (props.selection?.kind === 'node' ? (props.graph.nodes.get(props.selection.id) ?? null) : null))
const group = computed(() => (props.selection?.kind === 'group' ? (props.graph.groups.get(props.selection.id) ?? null) : null))
const line = computed(() => {
  const sel = props.selection
  return sel?.kind === 'edge' ? (drawnEdges(props.graph).find((l) => l.key === sel.key) ?? null) : null
})

const CHIP_KIND: Record<FlowChip['kind'], string> = { security_group: 'Security group', role: 'Role', waf: 'WAF' }
const nodeChips = computed(() => (node.value ? (props.flowChips?.get(node.value.uid) ?? []) : []))

const resourceLink = (id: number) => ({ name: 'resources', query: { open: String(id) } })

function stepType(step: MapNode): string {
  if (step.kind === 'internet') return 'Where the flow starts'
  if (step.kind === 'external') return 'Not in the inventory'
  return typeLabel(step.type)
}
const roleName = (uid: string) => uid.split('/').pop() ?? uid
const expandBlocked = computed(() => {
  if (node.value?.boundary) return `${boundaryLabel(node.value, props.connectionName)}. Make it the focus to explore its own connection.`
  return props.full ? FULL : node.value?.expanded ? 'Every connection is shown' : null
})

// ---- Header text.
const title = computed(() => {
  if (node.value) return nodeName(node.value)
  if (group.value) return `${group.value.count} ${group.value.resource_type ? typeLabel(group.value.resource_type) : 'resources'}`
  if (line.value) return line.value.type
  return 'Nothing selected'
})
const caption = computed(() => {
  const n = node.value
  if (n?.kind === 'resource' && n.type) return `${n.type} · ${n.region ? regionLabel(n.region) : '—'} · ${n.connection_id ? props.connectionName(n.connection_id) : '—'}`
  if (n?.kind === 'external') return 'Not in the inventory'
  if (n?.kind === 'any') return 'Wildcard grant (*)'
  if (group.value) {
    const anchor = props.graph.nodes.get(group.value.anchor_uid)
    return `${group.value.edge_type} ${group.value.direction === 'out' ? '←' : '→'} ${anchor ? nodeName(anchor) : group.value.anchor_uid}`
  }
  if (line.value) {
    const from = props.graph.nodes.get(line.value.source)
    const to = props.graph.nodes.get(line.value.target)
    return `${from ? nodeName(from) : line.value.source} → ${to ? nodeName(to) : line.value.target}`
  }
  return ''
})
defineExpose({ title, caption })

// ---- A group's members.
const PAGE = 20
const page = ref(1)
watch(group, () => (page.value = 1))
const members = useResource(
  async () => {
    const g = group.value
    if (!g || props.connectionId == null) return null
    return await unwrap(
      api.GET('/api/v1/map/group', {
        params: {
          query: {
            anchor: g.anchor_uid,
            connection_id: props.connectionId,
            direction: g.direction as 'out' | 'in',
            edge_type: g.edge_type,
            resource_type: g.resource_type,
            as_of: props.asOf,
            limit: PAGE,
            offset: (page.value - 1) * PAGE,
          },
        },
      }),
    )
  },
  { watch: [group, page, () => props.asOf, () => props.connectionId] },
)
function added(member: Schemas['GroupMember']): boolean {
  return props.graph.nodes.has(member.node.uid)
}

function pseudoText(n: MapNode): string {
  if (n.kind === 'internet') return 'Anyone on the internet. Its connections are what Argus rules and CloudFox found reachable from outside.'
  if (n.kind === 'admin') return 'Administrator access in this account: a principal that reaches it can do anything there.'
  if (n.kind === 'any') return 'Every resource of this service: a policy grants it on Resource "*". Narrow the policy to the resources the role needs.'
  return 'A host name that no collected resource owns: another account, a third party, or a type Argus does not collect.'
}
// A door's evidence and state read as words below the facts, not as JSON (ADR-0035, fifth amendment).
const EVIDENCE = new Set(['network', 'state'])
function attributes(edge: MapEdge): [string, string][] {
  return Object.entries(edge.attributes)
    .filter(([k]) => !EVIDENCE.has(k))
    .map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)])
}
function evidence(edge: MapEdge): { network: DoorInterface[]; state: string | null } | null {
  const network = edge.attributes.network
  if (!Array.isArray(network) || !network.length) return null
  const state = edge.attributes.state
  return { network: network as DoorInterface[], state: typeof state === 'string' ? state : null }
}
</script>

<template>
  <div class="panel-body">
    <header v-if="!framed && selection" class="head">
      <div class="titles">
        <h2 class="h2 title" tabindex="-1">{{ title }}</h2>
        <p v-if="caption" class="cap" :class="{ mono: !!line || !!group }">{{ caption }}</p>
      </div>
      <button type="button" class="icon-btn" aria-label="Close panel" @click="emit('close')">
        <AppIcon name="cross" :size="18" />
      </button>
    </header>

    <template v-if="node">
      <div class="actions">
        <span v-if="!flowChips" :title="expandBlocked ?? undefined">
          <button type="button" class="btn btn-secondary btn-sm" :disabled="!!expandBlocked" @click="emit('expand', node.uid)">
            <AppIcon name="expand" :size="16" />Expand
          </button>
        </span>
        <button v-if="node.kind !== 'external' && node.kind !== 'any'" type="button" class="btn btn-secondary btn-sm" @click="emit('focusHere', node.uid)">
          <AppIcon name="graph" :size="16" />{{ flowChips ? 'Explore around' : 'Focus here' }}
        </button>
        <RouterLink v-if="node.resource_id != null" class="btn btn-ghost btn-sm" :to="resourceLink(node.resource_id)" target="_blank">
          Open in Resources<span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span>
        </RouterLink>
      </div>
      <section v-if="flowPath && flowPath.length > 1" class="path" aria-labelledby="mp-path">
        <h3 id="mp-path" class="lbl">Path from the internet</h3>
        <ol class="steps">
          <li v-for="(step, i) in flowPath" :key="step.node.uid" :class="{ here: i === flowPath.length - 1 }" :style="{ '--type': typeDisc(step.node.kind, step.node.type).color }">
            <span class="dot" aria-hidden="true"><AppIcon :name="typeDisc(step.node.kind, step.node.type).icon" :size="13" /></span>
            <span class="step-text">
              <button v-if="i < flowPath.length - 1" type="button" class="step-name linkish" @click="emit('select', { kind: 'node', id: step.node.uid })">{{ nodeName(step.node) }}</button>
              <span v-else class="step-name" aria-current="step">{{ nodeName(step.node) }}</span>
              <span class="mono step-type">{{ stepType(step.node) }}</span>
              <span v-if="step.via" class="step-via">Through {{ roleName(step.via) }}: what its policies allow, not observed traffic.</span>
            </span>
          </li>
        </ol>
      </section>
      <section v-if="nodeChips.length" class="carries" aria-labelledby="mp-carries">
        <h3 id="mp-carries" class="lbl">Carries</h3>
        <ul class="rows">
          <li v-for="chip in nodeChips" :key="`${chip.kind}|${chip.chip_uid}`">
            <span class="chip-kind">{{ CHIP_KIND[chip.kind] }}</span>
            <span class="mono" :title="chip.chip_uid">{{ chip.name ?? chip.chip_uid }}</span>
          </li>
        </ul>
      </section>
      <ResourceDetail
        v-if="node.resource_id != null"
        :resource-id="node.resource_id"
        :as-of="asOf"
        :connection-name="connectionName"
        :resource-link="resourceLink"
        new-tab
      />
      <p v-else class="body">{{ pseudoText(node) }}</p>
    </template>

    <template v-else-if="group">
      <AlertBanner v-if="members.error.value" kind="fail">
        Members didn't load: {{ members.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="members.reload">Retry</button></template>
      </AlertBanner>
      <div v-else-if="!members.data.value" aria-busy="true" class="loading"><div v-for="n in 5" :key="n" class="skeleton sk-48"></div></div>
      <template v-else>
        <div class="table-wrap">
          <table class="table compact">
            <thead>
              <tr><th scope="col">Name</th><th scope="col">Region</th><th scope="col">Open findings</th><th scope="col"><span class="sr-only">Add</span></th></tr>
            </thead>
            <tbody>
              <tr v-for="m in members.data.value.items" :key="m.node.uid">
                <td class="name" :title="m.node.uid">{{ nodeName(m.node) }}</td>
                <td class="mono small">{{ m.node.region ? regionLabel(m.node.region) : '—' }}</td>
                <td>
                  <span v-if="worstOf(m.node).worst" class="findings"><SeverityTag :severity="worstOf(m.node).worst!" compact /><span class="mono">{{ worstOf(m.node).open }}</span></span>
                  <span v-else class="cap">None</span>
                </td>
                <td class="right">
                  <span :title="full && !added(m) ? FULL : undefined">
                    <button
                      type="button"
                      class="btn btn-secondary btn-sm add"
                      :disabled="added(m) || full"
                      :aria-label="added(m) ? `${nodeName(m.node)} is on the map` : `Add ${nodeName(m.node)} to the map`"
                      @click="emit('add', m)"
                    >
                      {{ added(m) ? 'Added' : 'Add' }}
                    </button>
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <AppPagination :total="members.data.value.total" :page="page" :limit="PAGE" noun="member" @change="page = $event" />
      </template>
      <RouterLink
        class="btn btn-ghost btn-sm see-all"
        :to="{ name: 'resources', query: { type: group.resource_type ?? undefined, connection: graph.nodes.get(group.anchor_uid)?.connection_id ?? undefined } }"
        target="_blank"
      >
        See all in Resources<span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span>
      </RouterLink>
    </template>

    <template v-else-if="line">
      <dl class="facts">
        <div><dt class="lbl">Type</dt><dd class="mono">{{ line.type }}</dd></div>
        <div>
          <dt class="lbl">From</dt>
          <dd><button type="button" class="link-btn" @click="emit('select', { kind: 'node', id: line.source })">{{ graph.nodes.get(line.source) ? nodeName(graph.nodes.get(line.source)!) : line.source }}</button></dd>
        </div>
        <div>
          <dt class="lbl">To</dt>
          <dd><button type="button" class="link-btn" @click="emit('select', { kind: 'node', id: line.target })">{{ graph.nodes.get(line.target) ? nodeName(graph.nodes.get(line.target)!) : line.target }}</button></dd>
        </div>
      </dl>
      <section v-for="e in line.edges" :key="e.id" class="block" :aria-label="`Found by ${originLabel(e.origin)}`">
        <h3 class="lbl origin"><span class="chip" :title="e.origin">{{ originLabel(e.origin) }}</span><span v-if="e.origin.startsWith('rule:')" class="mono rule">{{ e.origin.slice(5) }}</span></h3>
        <dl class="facts">
          <div><dt class="lbl">First seen</dt><dd class="mono">{{ e.first_seen }}</dd></div>
          <div><dt class="lbl">Last seen</dt><dd class="mono">{{ e.last_seen }}</dd></div>
          <div v-for="[k, v] in attributes(e)" :key="k" class="wide"><dt class="lbl">{{ k }}</dt><dd class="mono path">{{ v }}</dd></div>
        </dl>
        <template v-if="evidence(e)">
          <h4 class="lbl">Evidence</h4>
          <DoorEvidence :network="evidence(e)!.network" :state="evidence(e)!.state" />
        </template>
      </section>
    </template>
  </div>
</template>

<style scoped>
.panel-body {
  display: flex;
  flex-direction: column;
  gap: var(--s-20);
  min-width: 0;
}

.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--s-12);
}

.titles {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  min-width: 0;
}

.titles .h2,
.titles .cap {
  margin: 0;
  overflow-wrap: anywhere;
}

.title:focus {
  outline: none;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-8);
}

/* Path from the internet (Flow mode): discs joined by a dashed line, the node last. */
.steps {
  margin: var(--s-6) 0 0;
  padding: 0;
  list-style: none;
}

.steps li {
  position: relative;
  display: flex;
  gap: var(--s-10);
  align-items: flex-start;
  padding: var(--s-4) 0;
}

.steps li + li::before {
  content: '';
  position: absolute;
  left: 13px;
  top: -8px;
  height: 14px;
  border-left: 1px dashed var(--border-control);
}

.dot {
  flex: none;
  display: grid;
  place-items: center;
  width: 27px;
  height: 27px;
  border-radius: 50%;
  color: var(--type);
  background: color-mix(in srgb, var(--type) 14%, transparent);
}

.here .dot {
  box-shadow: 0 0 0 2px var(--accent);
}

.step-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
  padding-top: 2px;
}

.step-name {
  font-size: 12.5px;
  color: var(--text);
  overflow-wrap: anywhere;
  text-align: left;
}

.here .step-name {
  font-weight: 600;
}

.linkish {
  padding: 0;
  border: 0;
  background: none;
  font: inherit;
  font-size: 12.5px;
  cursor: pointer;
}

.linkish:hover {
  color: var(--link);
  text-decoration: underline;
}

.linkish:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

.step-type {
  font-size: 10.5px;
  color: var(--text-3);
}

.step-via {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-2);
}

.body {
  margin: 0;
  font-size: 13px;
  color: var(--text-2);
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.compact td,
.compact th {
  padding-top: var(--s-6);
  padding-bottom: var(--s-6);
}

.name {
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
}

.small {
  font-size: 12px;
}

.findings {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.add {
  height: 28px;
}

.see-all {
  align-self: flex-start;
}

.facts {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: var(--s-10) var(--s-20);
  font-size: 13px;
}

.facts dd {
  margin: 2px 0 0;
}

.facts .wide {
  grid-column: 1 / -1;
}

.path {
  overflow-wrap: anywhere;
}

.block {
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
}

.origin {
  display: flex;
  align-items: center;
  gap: var(--s-8);
  margin: 0;
}

.rule {
  font-size: 11px;
  color: var(--text-2);
  text-transform: none;
  letter-spacing: 0;
}

.link-btn {
  padding: 0;
  border: 0;
  background: none;
  color: var(--link);
  font: inherit;
  text-align: left;
  cursor: pointer;
  overflow-wrap: anywhere;
}

.link-btn:hover {
  color: var(--link-hover);
  text-decoration: underline;
}

.carries .rows {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  margin: var(--s-6) 0 0;
  padding: 0;
  list-style: none;
}

.carries li {
  display: flex;
  gap: var(--s-8);
  align-items: baseline;
  min-width: 0;
}

.chip-kind {
  flex: none;
  min-width: 112px;
  color: var(--text-2);
  font-size: 13px;
}
</style>
