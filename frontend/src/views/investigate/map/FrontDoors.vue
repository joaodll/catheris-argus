<script setup lang="ts">
/**
 * The Resource map's start state (docs/ui/screens.md, E11, Start state: Front doors): one list of
 * what faces the internet in one connection, open doors first, then the ones Argus cannot judge
 * (data is missing), then restricted ones, then what only CloudFox calls public (ADR-0035). A door opens its flow, the whole chain from it
 * (ADR-0036); one no flow starts from (CloudFox's alone) opens its neighbourhood (Explore). The
 * connection, search, filters and page live in the URL, so "Front doors" on the map comes back
 * here. The search narrows the doors by name, ARN or type ("S3"; 2026-10-15); Find a resource,
 * above, still jumps to any one resource. A door in a VPC opens its evidence under the why-line
 * (ADR-0035, fifth amendment).
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import MultiSelect from '@/components/MultiSelect.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import ReachBadge from '../ReachBadge.vue'
import DoorEvidence from './DoorEvidence.vue'
import { regionLabel } from '../labels'
import { FINDING_REACHES } from '../reachReason'
import { doorWhy } from './doorWhy'
import { nodeName, worstOf } from './mapGraph'
import { REACHES, REACH_LABEL, type MapState, type Reach } from './mapQuery'

const props = defineProps<{
  connections: Schemas['ConnectionOut'][]
  state: MapState
  focusLink: (uid: string) => RouteLocationRaw
  flowLink: (id: number) => RouteLocationRaw
}>()
// Each change goes to the URL; a new connection or filter starts at page 1.
const emit = defineEmits<{ change: [next: Partial<MapState>] }>()

const PAGE = 20
const chosen = computed(() => props.state.connection ?? props.connections[0]?.id ?? null)
const chosenName = computed(() => props.connections.find((c) => c.id === chosen.value)?.name ?? '')
const filtered = computed(() => Boolean(props.state.q) || props.state.reach.length > 0 || props.state.region.length > 0)

// The search filters as you type, 300 ms after the last key (the parent replaces the history entry).
const search = ref(props.state.q)
let typing: number | undefined
watch(search, (value) => {
  window.clearTimeout(typing)
  typing = window.setTimeout(() => {
    if (value.trim() !== props.state.q) emit('change', { q: value.trim(), page: 1 })
  }, 300)
})
watch(
  () => props.state.q,
  (q) => {
    if (q !== search.value.trim()) search.value = q
  },
)
onBeforeUnmount(() => window.clearTimeout(typing))

function clearFilters(): void {
  window.clearTimeout(typing)
  search.value = ''
  emit('change', { q: '', reach: [], region: [], page: 1 })
}

const facets = useResource(
  async () => (chosen.value == null ? null : unwrap(api.GET('/api/v1/resources/facets', { params: { query: { connection_id: chosen.value } } }))),
  { watch: [chosen] },
)
const reachOptions = REACHES.map((r) => ({ value: r, label: REACH_LABEL[r] }))
const regionOptions = computed(() => (facets.data.value?.regions ?? []).map((r) => ({ value: r, label: regionLabel(r), mono: true })))

const doors = useResource(
  async () => {
    if (chosen.value == null) return null
    const s = props.state
    const query = { connection_id: chosen.value, as_of: s.asOf, limit: PAGE, offset: (s.page - 1) * PAGE, q: s.q || null, reach: s.reach, region: s.region }
    return unwrap(api.GET('/api/v1/map/front-doors', { params: { query } }))
  },
  { watch: [chosen, () => props.state.page, () => props.state.q, () => props.state.reach, () => props.state.region, () => props.state.asOf] },
)

const rows = computed(() =>
  (doors.data.value?.items ?? []).map((d) => ({
    ...d,
    findings: worstOf(d.node),
    why: doorWhy(d),
    link: d.flow_id != null ? props.flowLink(d.flow_id) : props.focusLink(d.node.uid),
    exposure: exposureLink(d),
  })),
)

// Prowler's failing exposure checks on a door (ADR-0035, sixth amendment): Findings on this
// resource, Prowler only, every reach (the findings Argus judged).
function exposureLink(d: Schemas['FrontDoor']): { to: RouteLocationRaw; text: string } | null {
  if (!d.prowler_exposure || d.node.resource_id == null) return null
  const n = d.prowler_exposure
  return {
    to: { name: 'misconfigurations', query: { resource: String(d.node.resource_id), tool: 'prowler', reach: FINDING_REACHES } },
    text: `${n} exposure ${n === 1 ? 'check' : 'checks'} failing`,
  }
}
</script>

<template>
  <div class="doors">
    <div class="head">
      <div class="titles">
        <h2 id="doors-h" class="h2">Start from what the internet reaches</h2>
        <p class="cap">
          Each entry from the internet, with its reach: Argus checked its security groups, routing, network ACLs, auth and address lists. Choose one to follow its flow, or
          use Find a resource above to explore around any resource.
        </p>
      </div>
      <div class="controls">
        <div class="field search">
          <label class="lbl" for="doors-q">Search</label>
          <span class="search-wrap">
            <AppIcon name="search" :size="16" class="search-icon" />
            <input id="doors-q" v-model="search" class="input" type="search" placeholder="Name, ARN or type: S3, lambda…" maxlength="200" autocomplete="off">
          </span>
        </div>
        <div class="field conn">
          <label class="lbl" for="doors-conn">Connection</label>
          <select id="doors-conn" class="select" :value="chosen ?? ''" @change="emit('change', { connection: Number(($event.target as HTMLSelectElement).value), region: [], page: 1 })">
            <option v-for="c in connections" :key="c.id" :value="c.id">{{ c.name }}</option>
          </select>
        </div>
        <div class="field">
          <MultiSelect id="doors-reach" label="Reach" :options="reachOptions" :model-value="state.reach" @update:model-value="(v) => emit('change', { reach: v as Reach[], page: 1 })" />
        </div>
        <div class="field">
          <MultiSelect
            id="doors-region"
            label="Region"
            :options="regionOptions"
            :model-value="state.region"
            :status="facets.error.value ? 'error' : facets.data.value ? 'ready' : 'loading'"
            @update:model-value="(v) => emit('change', { region: v, page: 1 })"
          />
        </div>
        <button v-if="filtered" type="button" class="btn btn-ghost" @click="clearFilters">Clear filters</button>
      </div>
    </div>

    <EmptyState v-if="connections.length === 0" icon="graph" title="No connections yet." text="Add a connection in Administration, then run a scan." />
    <AlertBanner v-else-if="doors.error.value" kind="fail">
      Front doors didn't load: {{ doors.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="doors.reload">Retry</button></template>
    </AlertBanner>
    <div v-else-if="!doors.data.value" aria-busy="true" class="loading"><div v-for="n in 5" :key="n" class="skeleton sk-48"></div></div>
    <EmptyState v-else-if="doors.data.value.total === 0 && filtered" icon="info" title="No front doors match these filters.">
      <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
    </EmptyState>
    <EmptyState
      v-else-if="doors.data.value.total === 0"
      icon="globe"
      :title="`Nothing facing the internet was found for ${chosenName}.`"
      text="Entries appear after a Steampipe scan of this connection is ingested."
    />
    <template v-else>
      <div class="table-wrap">
        <table class="table stackable" aria-labelledby="doors-h">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Type</th>
              <th scope="col">Reach</th>
              <th scope="col">Resources</th>
              <th scope="col">Open findings</th>
              <th scope="col">Region</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in rows" :key="d.node.uid">
              <td data-label="Name">
                <RouterLink class="row-link name" :to="d.link" :title="d.node.uid">{{ nodeName(d.node) }}</RouterLink>
              </td>
              <td data-label="Type" class="mono small">{{ d.node.type ?? '—' }}</td>
              <td data-label="Reach">
                <div class="reach">
                  <ReachBadge door :reach="d.reach" />
                  <span v-if="d.why" class="why">{{ d.why }}</span>
                  <RouterLink v-if="d.exposure" class="exposure" :to="d.exposure.to">
                    <ToolChip tool="prowler" /><span>{{ d.exposure.text }}</span>
                  </RouterLink>
                  <!-- What the verdict rests on (ADR-0035, fifth amendment), on demand. -->
                  <details v-if="d.network.length" class="evidence">
                    <summary>Evidence</summary>
                    <DoorEvidence :network="d.network" :state="d.state" />
                  </details>
                </div>
              </td>
              <td data-label="Resources">
                <template v-if="d.resources != null">
                  <span class="mono">{{ d.resources }}</span><span v-if="d.truncated" class="cap"> · cut at the cap</span>
                </template>
                <span v-else class="cap">No flow: opens its neighbourhood</span>
              </td>
              <td data-label="Open findings">
                <span v-if="d.findings.worst" class="findings">
                  <SeverityTag :severity="d.findings.worst" compact /><span class="mono">{{ d.findings.open }}</span>
                </span>
                <span v-else class="cap">None</span>
              </td>
              <td data-label="Region" class="mono small">{{ d.node.region ? regionLabel(d.node.region) : '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <AppPagination :total="doors.data.value.total" :page="state.page" :limit="PAGE" noun="front door" @change="(p) => emit('change', { page: p })" />
    </template>
  </div>
</template>

<style scoped>
.doors {
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
  padding: var(--s-20);
}

.head {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--s-16);
}

.titles {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  max-width: 640px;
}

.titles .cap,
.titles .h2 {
  margin: 0;
}

.controls {
  display: flex;
  flex: 1 1 auto;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--s-16);
}

.conn {
  min-width: 220px;
}

.search {
  flex: 1 1 240px;
  max-width: 340px;
}

.search-wrap {
  position: relative;
  display: block;
}

.search-wrap .input {
  width: 100%;
  padding-left: 36px;
}

.search-icon {
  position: absolute;
  top: 50%;
  left: 12px;
  transform: translateY(-50%);
  color: var(--text-3);
  pointer-events: none;
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.small {
  font-size: 12px;
}

.reach {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--s-4);
}

.why {
  max-width: 320px;
  color: var(--text-2);
  font-size: 12px;
}

.exposure {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  color: var(--text-2);
  font-size: 12px;
  text-decoration: none;
}

.exposure:hover,
.exposure:focus-visible {
  color: var(--link);
  text-decoration: underline;
}

.evidence {
  max-width: 360px;
}

.evidence summary {
  cursor: pointer;
  color: var(--text-2);
  font-size: 12px;
}

.evidence[open] summary {
  margin-bottom: var(--s-8);
}

.findings {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
}
</style>
