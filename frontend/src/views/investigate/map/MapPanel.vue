<script setup lang="ts">
/**
 * The map's docked panel (ADR-0051): the selected resource, a group's members to add, or one
 * connection in words, with where it was found and its ports. On the Resource Map the resource is
 * as the inventory describes it (ResourceDetail, plain: its description, connections, tags and
 * configuration, with no security fact). On the Security Map it leads with its facts, each linked
 * to the list that counts it (mapFacts.ts), then the whole resource: findings, vulnerabilities,
 * the door from the internet and commands; a group's members show their facts. Not modal: the map stays usable beside it. The page frames it (docked,
 * overlaid, or as the detail sheet on a phone).
 */
import { computed, ref, watch } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import { useResource } from '@/composables/useResource'
import { originLabel, regionLabel } from '../labels'
import { edgeTitle } from '../edgeWords'
import ResourceDetail from '../ResourceDetail.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import ExploitMark from '../ExploitMark.vue'
import CountPill from './CountPill.vue'
import { factLinks, factSub, factsOf, marksOf, pillCount, worstOf } from './mapFacts'
import { boundaryLabel, drawnEdges, nodeName, type GraphState, type MapEdge, type MapNode, type Selection } from './mapGraph'
import { typeLabel } from './mapLanes'

const props = defineProps<{
  graph: GraphState
  selection: Selection | null
  full: boolean // the map holds 500 nodes: nothing more can be added
  connectionName: (id: number) => string
  // The connection the map walks: a group's members are read in it.
  connectionId: number | null
  // Shown as the sheet on a phone: the sheet has its own title and close button.
  framed?: boolean
  map?: 'resource' | 'security'
}>()
const security = computed(() => props.map === 'security')
const emit = defineEmits<{
  close: []
  expand: [uid: string]
  focusHere: [uid: string]
  add: [member: { node: MapNode; edge: MapEdge }]
  select: [selection: Selection]
}>()

const FULL = 'Showing 500 resources, the most this map draws. Reset, or show fewer kinds of connection, to see others.'
const node = computed(() => (props.selection?.kind === 'node' ? (props.graph.nodes.get(props.selection.id) ?? null) : null))
const group = computed(() => (props.selection?.kind === 'group' ? (props.graph.groups.get(props.selection.id) ?? null) : null))
const line = computed(() => {
  const sel = props.selection
  return sel?.kind === 'edge' ? (drawnEdges(props.graph).find((l) => l.key === sel.key) ?? null) : null
})

const resourceLink = (id: number) => ({ name: 'resources', query: { open: String(id) } })

const expandBlocked = computed(() => {
  if (node.value?.boundary) return `${boundaryLabel(node.value, props.connectionName)}. Make it the focus to explore its own connection.`
  return props.full ? FULL : node.value?.expanded ? 'Every connection is shown' : null
})

// ---- Header text.
const title = computed(() => {
  if (node.value) return nodeName(node.value)
  if (group.value) return `${group.value.count} ${group.value.resource_type ? typeLabel(group.value.resource_type) : 'resources'}`
  if (line.value) return edgeTitle(line.value.type, line.value.target)
  return 'Nothing selected'
})
const caption = computed(() => {
  const n = node.value
  if (n?.kind === 'resource' && n.type) return `${n.type} · ${n.region ? regionLabel(n.region) : '—'} · ${n.connection_id ? props.connectionName(n.connection_id) : '—'}`
  if (n?.kind === 'external') return 'Not in the inventory'
  if (n?.kind === 'any') return 'Wildcard grant (*)'
  if (group.value) {
    const anchor = props.graph.nodes.get(group.value.anchor_uid)
    return `${edgeTitle(group.value.edge_type)} ${group.value.direction === 'out' ? '←' : '→'} ${anchor ? nodeName(anchor) : group.value.anchor_uid}`
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
    const query = {
      anchor: g.anchor_uid,
      connection_id: props.connectionId,
      direction: g.direction as 'out' | 'in',
      edge_type: g.edge_type,
      resource_type: g.resource_type,
      limit: PAGE,
      offset: (page.value - 1) * PAGE,
    }
    // The Resource Map reads only its plain route; the Security Map's members carry facts.
    return security.value
      ? await unwrap(api.GET('/api/v1/map/security/group', { params: { query } }))
      : await unwrap(api.GET('/api/v1/map/group', { params: { query } }))
  },
  { watch: [group, page, () => props.connectionId, security] },
)

// ---- The Security Map's facts on the selected resource, each linked to the list counting it.
const facts = computed(() => (security.value ? factsOf(node.value) : null))
const links = computed(() => (node.value?.resource_id != null ? factLinks(node.value.resource_id) : null))
const nodeConnection = computed(() => (node.value?.connection_id != null ? props.connectionName(node.value.connection_id) : 'its account'))
const memberPill = (m: Schemas['GroupMember'] | Schemas['SecurityGroupMember']) => {
  const f = factsOf(m.node as MapNode)
  const count = pillCount(f)
  const worst = worstOf(f)
  return count && worst ? { count, severity: worst } : null
}
const memberMarks = (m: Schemas['GroupMember'] | Schemas['SecurityGroupMember']) => marksOf(factsOf(m.node as MapNode))
const memberWords = (m: Schemas['GroupMember'] | Schemas['SecurityGroupMember']) => factSub(factsOf(m.node as MapNode)).join(' · ') || 'No open findings'
function added(member: Schemas['GroupMember']): boolean {
  return props.graph.nodes.has(member.node.uid)
}

function pseudoText(n: MapNode): string {
  if (n.kind === 'internet') return 'Anyone on the internet. Its lines are what Argus\'s rules route from it and what CloudFox found it reaches.'
  if (n.kind === 'admin') return 'Administrator access in this account: a principal that reaches it can do anything there.'
  if (n.kind === 'any') return 'Every resource of this service: a policy grants it on Resource "*".'
  return 'A host name that no collected resource owns: another account, a third party, or a type Argus does not collect.'
}
/** An edge's ports, the only attributes a map edge carries: "tcp/443", "tcp/8000-8100",
 * "All traffic". Null when it has none. */
function ports(edge: MapEdge): string | null {
  const a = edge.attributes
  const protocol = typeof a.protocol === 'string' || typeof a.protocol === 'number' ? String(a.protocol).toLowerCase() : null
  if (protocol === '-1' || protocol === 'all') return 'All traffic'
  const from = a.from_port ?? a.port
  const to = a.to_port
  if (from == null || from === '') return protocol ? `${protocol}, any port` : null
  const range = to != null && to !== '' && String(to) !== String(from) ? `${from}-${to}` : String(from)
  return `${protocol ?? 'tcp'}/${range}`
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
        <span :title="expandBlocked ?? undefined">
          <button type="button" class="btn btn-secondary btn-sm" :disabled="!!expandBlocked" @click="emit('expand', node.uid)">
            <AppIcon name="expand" :size="16" />Expand
          </button>
        </span>
        <button v-if="node.kind !== 'external' && node.kind !== 'any'" type="button" class="btn btn-secondary btn-sm" @click="emit('focusHere', node.uid)">
          <AppIcon name="graph" :size="16" />Focus here
        </button>
        <RouterLink v-if="node.resource_id != null" class="btn btn-ghost btn-sm" :to="resourceLink(node.resource_id)" target="_blank">
          Open in Resources<span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span>
        </RouterLink>
      </div>
      <section v-if="security && node.resource_id != null && facts && links" class="sec-facts" aria-labelledby="mp-facts">
        <h3 id="mp-facts" class="lbl">Security facts</h3>
        <ul class="fact-rows">
          <li>
            <AppIcon name="flag" :size="16" class="glyph" />
            <span v-if="facts.misconfigurations == null" class="cap">Misconfigurations: not covered (Prowler and CloudFox have not scanned {{ nodeConnection }})</span>
            <span v-else-if="facts.misconfigurations.open === 0" class="body">No open misconfigurations</span>
            <RouterLink v-else :to="links.misconfigurations" target="_blank" class="fact-link">
              <SeverityTag v-if="facts.misconfigurations.worst" :severity="facts.misconfigurations.worst" compact />
              <span><span class="mono">{{ facts.misconfigurations.open.toLocaleString('en-US') }}</span> open {{ facts.misconfigurations.open === 1 ? 'misconfiguration' : 'misconfigurations' }}</span>
              <span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span>
            </RouterLink>
          </li>
          <li v-if="facts.vulnerabilities">
            <AppIcon name="bug" :size="16" class="glyph" />
            <span v-if="!facts.vulnerabilities.scanned && facts.vulnerabilities.open === 0" class="cap">Not scanned for vulnerabilities</span>
            <span v-else-if="facts.vulnerabilities.open === 0" class="body">No open vulnerabilities</span>
            <RouterLink v-else :to="links.vulnerabilities" target="_blank" class="fact-link">
              <span><span class="mono">{{ facts.vulnerabilities.open.toLocaleString('en-US') }}</span> open {{ facts.vulnerabilities.open === 1 ? 'vulnerability' : 'vulnerabilities' }}</span>
              <ExploitMark v-if="facts.vulnerabilities.exploitable > 0" :count="facts.vulnerabilities.exploitable" />
              <span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span>
            </RouterLink>
          </li>
          <li v-if="facts.internet_reachable">
            <AppIcon name="globe" :size="16" class="glyph" />
            <RouterLink :to="links.internet" target="_blank" class="fact-link">
              <span>Reachable from the internet</span>
              <span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span>
            </RouterLink>
          </li>
        </ul>
      </section>
      <ResourceDetail
        v-if="node.resource_id != null"
        :resource-id="node.resource_id"
        :connection-name="connectionName"
        :resource-link="resourceLink"
        :plain="!security"
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
              <tr><th scope="col">Name</th><th scope="col">Region</th><th v-if="security" scope="col">Facts</th><th scope="col"><span class="sr-only">Add</span></th></tr>
            </thead>
            <tbody>
              <tr v-for="m in members.data.value.items" :key="m.node.uid">
                <td class="name" :title="m.node.uid">{{ nodeName(m.node) }}</td>
                <td class="mono small">{{ m.node.region ? regionLabel(m.node.region) : '—' }}</td>
                <td v-if="security" class="member-facts" :title="memberWords(m)">
                  <CountPill v-if="memberPill(m)" :count="memberPill(m)!.count" :severity="memberPill(m)!.severity" base="var(--surface)" />
                  <span v-else class="soft" aria-hidden="true">—</span>
                  <AppIcon v-if="memberMarks(m).internet" name="globe" :size="14" :stroke="1.8" />
                  <AppIcon v-if="memberMarks(m).vulnerable" name="bug" :size="14" :stroke="1.8" />
                  <AppIcon v-if="memberMarks(m).exploit" name="warning" :size="14" :stroke="1.8" class="exploit" />
                  <span class="sr-only">{{ memberWords(m) }}</span>
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
      <!-- Members Argus has no type for are not in the inventory: Resources has no list of them. -->
      <RouterLink
        v-if="group.resource_type"
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
          <div v-if="ports(e)" class="wide"><dt class="lbl">Ports</dt><dd class="mono">{{ ports(e) }}</dd></div>
        </dl>
      </section>
    </template>
  </div>
</template>

<style scoped>
/* The Security Map's facts on the resource (spec frontend/4242ef35, 7). */
.sec-facts {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.sec-facts .lbl {
  margin: 0;
}

.fact-rows {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: var(--s-8);
  font-size: 13px;
}

.fact-rows li {
  display: flex;
  align-items: flex-start;
  gap: var(--s-8);
}

.fact-rows .glyph {
  flex: none;
  margin-top: 2px;
  color: var(--text-2);
}

.fact-rows .cap,
.fact-rows .body {
  margin: 0;
}

.fact-link {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6);
}

.member-facts {
  white-space: nowrap;
}

.member-facts > * {
  vertical-align: middle;
}

.member-facts > * + * {
  margin-left: 4px;
}

.member-facts .exploit {
  color: var(--text);
}

.member-facts :deep(svg) {
  color: var(--text-2);
}

.soft {
  color: var(--text-3);
}

@media (max-width: 400px) {
  .member-facts {
    white-space: normal;
  }
}
.facts {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 6px;
  font-size: 13px;
}

.facts li {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

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
</style>
