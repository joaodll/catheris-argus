<script setup lang="ts">
/**
 * The Resource map's docked panel (docs/ui/screens.md, E11, Resource panel): what each tool says
 * about the selected resource (ResourceDetail, the same body as the Resources sheet, without its
 * "From the internet" block: the map shows connections, not reach, round M3a), a group's members
 * to add, or one connection in words, with its origins and ports. Not modal: the map stays usable
 * beside it. The page frames it (docked, overlaid, or as the detail sheet on a phone).
 */
import { computed, ref, watch } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import { useResource } from '@/composables/useResource'
import { originLabel, regionLabel } from '../labels'
import { edgeTitle } from '../edgeWords'
import ExploitMark from '../ExploitMark.vue'
import ResourceDetail from '../ResourceDetail.vue'
import { boundaryLabel, drawnEdges, nodeName, worstOf, type GraphState, type MapEdge, type MapNode, type Selection } from './mapGraph'
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
const misconfigurations = computed(() => (node.value ? worstOf(node.value).open : 0))
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
            limit: PAGE,
            offset: (page.value - 1) * PAGE,
          },
        },
      }),
    )
  },
  { watch: [group, page, () => props.connectionId] },
)
function added(member: Schemas['GroupMember']): boolean {
  return props.graph.nodes.has(member.node.uid)
}

function pseudoText(n: MapNode): string {
  if (n.kind === 'internet') return 'Anyone on the internet. Its lines are what Argus\'s rules route from it and what CloudFox found it reaches; Attack paths says what each one exposes.'
  if (n.kind === 'admin') return 'Administrator access in this account: a principal that reaches it can do anything there.'
  if (n.kind === 'any') return 'Every resource of this service: a policy grants it on Resource "*". Narrow the policy to the resources the role needs.'
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
      <ul v-if="misconfigurations || node.vulnerabilities || node.attack_paths" class="facts" aria-label="What is known about it">
        <li v-if="misconfigurations && node.resource_id != null">
          <RouterLink :to="{ name: 'misconfigurations', query: { resource: String(node.resource_id) } }" target="_blank">{{ misconfigurations }} {{ misconfigurations === 1 ? 'misconfiguration' : 'misconfigurations' }}<span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span></RouterLink>
        </li>
        <li v-if="node.vulnerabilities && node.resource_id != null">
          <RouterLink :to="{ name: 'vulnerabilities', query: { resource: String(node.resource_id) } }" target="_blank">{{ node.vulnerabilities.open }} {{ node.vulnerabilities.open === 1 ? 'CVE' : 'CVEs' }}<span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span></RouterLink>
          <ExploitMark v-if="node.vulnerabilities.exploitable" :count="node.vulnerabilities.exploitable" />
        </li>
        <li v-if="node.attack_paths">
          <RouterLink :to="{ name: 'attack-paths', query: { through: node.uid } }" target="_blank">On {{ node.attack_paths.on }} attack {{ node.attack_paths.on === 1 ? 'path' : 'paths' }}<template v-if="node.attack_paths.entry">, entry of {{ node.attack_paths.entry }}</template><span class="sr-only"> (opens in a new tab)</span><span aria-hidden="true">↗</span></RouterLink>
        </li>
      </ul>
      <ResourceDetail
        v-if="node.resource_id != null"
        :resource-id="node.resource_id"
        :connection-name="connectionName"
        :resource-link="resourceLink"
        hide-internet
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
          <div v-if="ports(e)" class="wide"><dt class="lbl">Ports</dt><dd class="mono">{{ ports(e) }}</dd></div>
        </dl>
      </section>
    </template>
  </div>
</template>

<style scoped>
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
