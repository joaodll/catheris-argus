<script setup lang="ts">
/**
 * The Resource map as tables (docs/ui/screens.md, E11, List view): the same nodes and edges as
 * the canvas, and its accessible equivalent. Choosing a name selects it and opens the panel.
 */
import { computed, ref, watch } from 'vue'
import AppPagination from '@/components/AppPagination.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import { degree, drawnEdges, groupNodeId, nodeName, worstOf, worstRank, type GraphState, type Selection } from './mapGraph'
import { hopColumns, hopLabel, typeLabel } from './mapLanes'

// The same columns as the canvas: the flow's steps, or hops from the focus (mapLanes.ts).
const props = defineProps<{
  graph: GraphState
  selection: Selection | null
  focus: string | null
  flow: { columns: ReadonlyMap<string, number>; label: (col: number) => string } | null
}>()
const emit = defineEmits<{ select: [selection: Selection] }>()

const PAGE = 20
const nodePage = ref(1)
const edgePage = ref(1)
watch(
  () => props.graph,
  () => {
    nodePage.value = 1
    edgePage.value = 1
  },
)

const position = computed<{ col: (uid: string) => number; label: (col: number) => string }>(() => {
  if (props.flow) {
    const flow = props.flow
    return { col: (uid) => flow.columns.get(uid) ?? Number.MAX_SAFE_INTEGER, label: flow.label }
  }
  const cols = hopColumns(
    [...props.graph.nodes.keys()],
    drawnEdges(props.graph).map((l) => ({ source: l.source, target: l.target })),
    props.focus,
  )
  const focused = props.focus != null && cols.has(props.focus)
  return { col: (uid) => cols.get(uid) ?? 0, label: (col) => hopLabel(col, focused) }
})
const nodes = computed(() =>
  [...props.graph.nodes.values()]
    .map((n) => ({ node: n, name: nodeName(n), col: position.value.col(n.uid), findings: worstOf(n), degree: degree(props.graph, n.uid) }))
    .sort((a, b) => a.col - b.col || worstRank(a.node) - worstRank(b.node) || a.name.localeCompare(b.name)),
)
const groups = computed(() => [...props.graph.groups.values()])
const lines = computed(() => drawnEdges(props.graph))
const name = (uid: string): string => {
  const n = props.graph.nodes.get(uid)
  if (n) return nodeName(n)
  const g = groups.value.find((x) => groupNodeId(x) === uid)
  return g ? `${g.count} ${g.resource_type ? typeLabel(g.resource_type) : 'resources'}` : uid
}
const ORIGIN: Record<string, string> = { rule: 'Rule', cloudfox: 'CloudFox', manual: 'Manual', probe: 'Probe' }
const pageOf = <T,>(list: T[], page: number): T[] => list.slice((page - 1) * PAGE, page * PAGE)
const selectedId = computed(() => (props.selection?.kind === 'node' ? props.selection.id : null))
</script>

<template>
  <div class="list">
    <section aria-labelledby="ml-nodes">
      <h3 id="ml-nodes" class="lbl">Resources</h3>
      <div class="table-wrap">
        <table class="table stackable">
          <thead>
            <tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Position</th><th scope="col" class="right">Connections</th><th scope="col">Open findings</th></tr>
          </thead>
          <tbody>
            <tr v-for="row in pageOf(nodes, nodePage)" :key="row.node.uid" :class="{ current: row.node.uid === selectedId }">
              <td data-label="Name">
                <button type="button" class="row-link" :title="row.node.uid" :aria-current="row.node.uid === selectedId ? 'true' : undefined" @click="emit('select', { kind: 'node', id: row.node.uid })">
                  {{ row.name }}
                </button>
              </td>
              <td data-label="Type" class="mono small">{{ row.node.type ?? typeLabel(null) }}</td>
              <td data-label="Position">{{ position.label(row.col) }}</td>
              <td data-label="Connections" class="right mono">{{ row.degree }}</td>
              <td data-label="Open findings">
                <span v-if="row.findings.worst" class="findings"><SeverityTag :severity="row.findings.worst" compact /><span class="mono">{{ row.findings.open }}</span></span>
                <span v-else class="cap">None</span>
              </td>
            </tr>
            <tr v-for="g in groups" :key="g.id">
              <td data-label="Name">
                <button type="button" class="row-link" @click="emit('select', { kind: 'group', id: g.id })">
                  <span class="mono">{{ g.count }}</span> {{ g.resource_type ? typeLabel(g.resource_type) : 'resources' }}
                </button>
              </td>
              <td data-label="Type" class="mono small">{{ g.resource_type ?? '—' }}</td>
              <td data-label="Position">Group</td>
              <td data-label="Connections" class="right mono">{{ g.count }}</td>
              <td data-label="Open findings"><span class="cap">See the group</span></td>
            </tr>
          </tbody>
        </table>
      </div>
      <AppPagination :total="nodes.length" :page="nodePage" :limit="PAGE" noun="resource" @change="nodePage = $event" />
    </section>

    <section aria-labelledby="ml-edges">
      <h3 id="ml-edges" class="lbl">Connections</h3>
      <p v-if="lines.length === 0" class="cap">No connections in the chosen layers.</p>
      <template v-else>
        <div class="table-wrap">
          <table class="table stackable">
            <thead><tr><th scope="col">From</th><th scope="col">Edge type</th><th scope="col">To</th><th scope="col">Origins</th></tr></thead>
            <tbody>
              <tr v-for="l in pageOf(lines, edgePage)" :key="l.key">
                <td data-label="From">{{ name(l.source) }}</td>
                <td data-label="Edge type">
                  <button v-if="!l.group" type="button" class="row-link mono small" @click="emit('select', { kind: 'edge', key: l.key })">{{ l.type }}</button>
                  <span v-else class="mono small">{{ l.type }}</span>
                </td>
                <td data-label="To">{{ name(l.target) }}</td>
                <td data-label="Origins"><span class="chips"><span v-for="f in l.families" :key="f" class="chip">{{ ORIGIN[f] ?? f }}</span></span></td>
              </tr>
            </tbody>
          </table>
        </div>
        <AppPagination :total="lines.length" :page="edgePage" :limit="PAGE" noun="connection" @change="edgePage = $event" />
      </template>
    </section>
  </div>
</template>

<style scoped>
.list {
  display: flex;
  flex-direction: column;
  gap: var(--s-24);
  padding: var(--s-20);
}

section {
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
}

section > .lbl,
section > .cap {
  margin: 0;
}

.small {
  font-size: 12px;
}

.findings {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.chips {
  display: inline-flex;
  flex-wrap: wrap;
  gap: var(--s-6);
}

tr.current > td {
  background: var(--accent-wash);
}
</style>
