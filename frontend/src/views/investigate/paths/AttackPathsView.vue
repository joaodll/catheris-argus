<script setup lang="ts">
/**
 * Investigate -> Attack paths (docs/ui/screens.md, E12; ADR-0028, fourth amendment): the chains
 * that let an attacker get from the internet, or a foothold, to something that matters, and
 * which link to break. One search (ADR-0037) chains CloudFox edges, relationship-rule edges and
 * failing Prowler checks from every internet entry; every row names the tools behind it and how
 * sure Argus is (its weakest step). Filters, order and page live in the URL (pathFilters.ts);
 * ?path=<id> opens one path in place of the table.
 */
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import FilterBar from '@/components/FilterBar.vue'
import MultiSelect, { type MultiOption } from '@/components/MultiSelect.vue'
import PageHeader from '@/components/PageHeader.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import SortHeader from '@/components/SortHeader.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { SEVERITIES, SEVERITY_LABEL, type Severity } from '@/views/overview/severity'
import { uidTail } from '../labels'
import { CONFIDENCE_LABEL, CONFIDENCE_MEANING, type Confidence } from './confidence'
import ConfidenceBadge from './ConfidenceBadge.vue'
import PathDetail from './PathDetail.vue'
import {
  type PathFilters,
  type PathOrder,
  isPathFiltered,
  parsePage,
  parsePathFilters,
  parsePathId,
  parsePathOrder,
  pathApiFilters,
  pathFiltersToQuery,
  toggleDate,
} from './pathFilters'
import { pathLine } from './pathWords'

const PAGE = 20
const route = useRoute()
const router = useRouter()

const filters = computed(() => parsePathFilters(route.query))
const order = computed(() => parsePathOrder(route.query))
const page = computed(() => parsePage(route.query))
const pathId = computed(() => parsePathId(route.query))

function navigate(next: { filters?: PathFilters; order?: PathOrder; page?: number; path?: number | null }, how: 'push' | 'replace' = 'push'): void {
  const o = next.order ?? order.value
  const p = next.page ?? (next.filters || next.order ? 1 : page.value)
  void router[how]({
    query: {
      ...pathFiltersToQuery(next.filters ?? filters.value),
      order: o === 'severity' ? undefined : o,
      page: p > 1 ? String(p) : undefined,
      path: next.path === undefined ? (pathId.value == null ? undefined : String(pathId.value)) : next.path == null ? undefined : String(next.path),
    },
  })
}
function set<K extends keyof PathFilters>(key: K, value: PathFilters[K]): void {
  navigate({ filters: { ...filters.value, [key]: value } })
}
function clearFilters(): void {
  navigate({ filters: parsePathFilters({}) })
}

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
function connectionName(id: number): string {
  return connections.data.value?.find((c) => c.id === id)?.name ?? `Connection ${id}`
}
const facets = useResource(() => unwrap(api.GET('/api/v1/attack-paths/facets', { params: { query: { connection_id: filters.value.connection } } })), {
  watch: [() => filters.value.connection],
})
const facetStatus = computed(() => (facets.error.value ? 'error' : facets.data.value ? 'ready' : 'loading'))
const severityOptions: MultiOption[] = SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))
const categoryOptions = computed<MultiOption[]>(() => (facets.data.value?.categories ?? []).map((c) => ({ value: c, label: c })))
const kindOptions = computed<MultiOption[]>(() => (facets.data.value?.kinds ?? []).map((k) => ({ value: k.id, label: k.name ?? k.id })))
const latentHidden = computed(() => !filters.value.confidence.length && (facets.data.value?.confidences ?? []).includes('blocked'))
const confidenceOptions = computed<MultiOption[]>(() => (facets.data.value?.confidences ?? []).map((c) => ({ value: c, label: CONFIDENCE_LABEL[c] })))

// The resource of a "Through" filter, by name.
const through = useResource(
  async () => {
    const uid = filters.value.through
    if (!uid) return null
    const found = await unwrap(api.GET('/api/v1/resources', { params: { query: { q: uid, limit: 5, include_deleted: true } } }))
    return found.items.find((r) => r.resource_uid === uid) ?? null
  },
  { watch: [() => filters.value.through] },
)
const throughName = computed(() => {
  const uid = filters.value.through
  if (!uid) return ''
  const r = through.data.value
  return r ? (r.name ?? r.native_id) : uidTail(uid)
})

const list = useResource(
  async () => {
    if (pathId.value != null) return null
    return await unwrap(
      api.GET('/api/v1/attack-paths', {
        params: { query: { ...pathApiFilters(filters.value), order: order.value, limit: PAGE, offset: (page.value - 1) * PAGE } },
      }),
    )
  },
  { watch: [() => JSON.stringify([filters.value, order.value, page.value, pathId.value])] },
)
// The page no longer exists (the list shrank): show the last one.
watch(
  () => list.data.value,
  (data) => {
    if (!data || data.items.length > 0 || data.total === 0) return
    const last = Math.max(1, Math.ceil(data.total / PAGE))
    if (page.value > last) navigate({ page: last }, 'replace')
  },
)
const filtered = computed(() => isPathFiltered(filters.value))
const chosenConnection = computed(() => (filters.value.connection ? connectionName(filters.value.connection) : null))

const TOOL_EVIDENCE = ['cloudfox', 'prowler']
function evidence(p: Schemas['PathOut']): { rule: boolean; tools: string[] } {
  const tools: string[] = p.evidence.filter((e) => e === 'cloudfox')
  if (p.has_failing) tools.push('prowler')
  return { rule: p.evidence.includes('rule'), tools: TOOL_EVIDENCE.filter((t) => tools.includes(t)) }
}

// An open path puts its rule name in front of the page title.
const pageTitle = document.title
const openName = ref<string | null>(null)
watch(
  [pathId, openName],
  ([id, name]) => {
    document.title = id != null && name ? `${name} · ${pageTitle}` : pageTitle
  },
  { immediate: true },
)
function onLoaded(path: Schemas['PathDetail'] | null): void {
  openName.value = path ? (path.rule?.name ?? path.rule_name ?? path.rule_id) : null
}
const dataThrough = computed(() => list.data.value?.data_through ?? null)
</script>

<template>
  <!-- A path is a detail page (design-system.md, Page header): a breadcrumb back to the list,
       whose filters stay in the URL, then PathDetail's header card. -->
  <template v-if="pathId != null">
    <nav class="breadcrumb" aria-label="Breadcrumb">
      <RouterLink :to="{ query: { ...route.query, path: undefined } }"><AppIcon name="chevron" :size="13" :stroke="2.2" class="back-icon" />Attack paths</RouterLink>
      <span class="sep" aria-hidden="true">/</span>
      <span aria-current="page">{{ openName ?? 'Attack path' }}</span>
    </nav>
    <PathDetail :path-id="pathId" :connection-name="connectionName" @loaded="onLoaded">
      <template #back>
        <RouterLink class="btn btn-secondary" :to="{ query: { ...route.query, path: undefined } }">← Attack paths</RouterLink>
      </template>
    </PathDetail>
  </template>

  <template v-else>
    <PageHeader title="Attack paths">
      <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
    </PageHeader>
    <FilterBar :active="filtered" label="Filters" @clear="clearFilters">
      <MultiSelect id="ap-sev" label="Severity" :options="severityOptions" :model-value="filters.severity" @update:model-value="set('severity', $event as Severity[])" />
      <MultiSelect id="ap-cat" label="Category" :options="categoryOptions" :status="facetStatus" :model-value="filters.category" @update:model-value="set('category', $event)" />
      <MultiSelect id="ap-kind" label="Kind" :options="kindOptions" :status="facetStatus" :model-value="filters.kind" @update:model-value="set('kind', $event)" />
      <MultiSelect
        id="ap-conf"
        label="Confidence"
        :options="confidenceOptions"
        :status="facetStatus"
        :model-value="filters.confidence"
        @update:model-value="set('confidence', $event as Confidence[])"
      />
      <div class="field">
        <label class="lbl" for="ap-conn">Connection</label>
        <select id="ap-conn" class="select" :value="filters.connection ?? ''" @change="set('connection', Number(($event.target as HTMLSelectElement).value) || null)">
          <option value="">All connections</option>
          <option v-for="c in connections.data.value ?? []" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </div>
      <div class="field">
        <span id="ap-state" class="lbl">State</span>
        <div class="segmented" role="group" aria-labelledby="ap-state">
          <button type="button" :aria-pressed="filters.state === 'open'" @click="set('state', 'open')">Open</button>
          <button type="button" :aria-pressed="filters.state === 'resolved'" @click="set('state', 'resolved')">Resolved</button>
        </div>
      </div>
      <span v-if="filters.through" class="chip through" :title="filters.through">
        Through: {{ throughName }}
        <button type="button" class="chip-x" :aria-label="`Remove the filter Through: ${throughName}`" @click="set('through', null)"><AppIcon name="cross" :size="12" :stroke="2.4" /></button>
      </span>
    </FilterBar>

    <!-- The Platform's list panel: a header bar, the table edge to edge, a footer bar. -->
    <section class="card panel" aria-labelledby="ap-h">
      <div class="panel-h">
        <div class="titles">
          <h2 id="ap-h" class="h2">{{ filters.state === 'open' ? 'Open attack paths' : 'Resolved attack paths' }}</h2>
          <span class="cap">Worst first. Argus searches from every internet entry through its rules' edges, CloudFox's and failing Prowler checks; a path is as sure as its weakest step. Read-only.</span>
        </div>
      </div>

      <!-- Latent paths (Blocked) start at a door Argus found closed: listed only when asked for (ADR-0037, amended). -->
      <div v-if="latentHidden" class="panel-body">
        <AlertBanner kind="info">
          Latent paths are hidden: they start at a door Argus found closed, and show what one change would open.
          <template #action><button type="button" class="btn btn-secondary btn-sm" @click="set('confidence', ['blocked'])">Show latent paths</button></template>
        </AlertBanner>
      </div>
      <div v-if="list.error.value" class="panel-body">
        <AlertBanner kind="fail">
          Attack paths didn't load: {{ list.error.value }}
          <template #action><button type="button" class="btn btn-secondary btn-sm" @click="list.reload">Retry</button></template>
        </AlertBanner>
      </div>
      <div v-else-if="!list.data.value" aria-busy="true" class="panel-body loading"><div v-for="n in 5" :key="n" class="skeleton sk-48"></div></div>
      <div v-else-if="list.data.value.total === 0" class="panel-body">
        <EmptyState
          v-if="filters.connection && !dataThrough"
          icon="route"
          :title="`Not covered: neither Steampipe nor CloudFox has scanned ${chosenConnection}.`"
          text="Attack paths appear when a Steampipe or CloudFox scan of this connection is ingested."
        />
        <EmptyState v-else-if="filtered" icon="info" title="No attack paths match these filters.">
          <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
        </EmptyState>
        <EmptyState
          v-else
          icon="route"
          title="No open attack paths."
          text="Paths appear when a Steampipe or CloudFox scan is ingested: Argus searches from every internet entry through its rules' edges, CloudFox's and failing Prowler checks."
        />
      </div>
      <template v-else>
        <div class="table-wrap table-fit">
          <table class="table stackable stack-narrow dense paths-table">
            <thead>
              <tr>
                <SortHeader label="Severity" :direction="order === 'severity' ? 'desc' : null" desc-text="worst first" asc-text="worst first" @toggle="navigate({ order: 'severity' })" />
                <th scope="col">Path</th>
                <th scope="col">Confidence</th>
                <th scope="col">Category</th>
                <th scope="col">Connection</th>
                <SortHeader
                  label="Last seen"
                  class="right"
                  :direction="order === 'last_seen_desc' ? 'desc' : order === 'last_seen_asc' ? 'asc' : null"
                  desc-text="newest first"
                  asc-text="oldest first"
                  @toggle="navigate({ order: toggleDate(order, 'last_seen') })"
                />
              </tr>
            </thead>
            <tbody>
              <tr v-for="p in list.data.value.items" :key="p.id">
                <td data-label="Severity"><SeverityTag :severity="p.severity" /></td>
                <td data-label="Path" class="path-cell">
                  <RouterLink class="path-link" :to="{ query: { ...route.query, path: String(p.id) } }">{{ p.rule_name ?? p.rule_id }}</RouterLink>
                  <span class="mono summary">{{ pathLine(p) }}</span>
                </td>
                <td data-label="Confidence">
                  <ConfidenceBadge v-if="p.confidence" :level="p.confidence" :why="CONFIDENCE_MEANING[p.confidence]" />
                  <span v-else class="cap">Not rated</span>
                </td>
                <td data-label="Category" class="category">
                  <span>{{ p.category }}</span>
                  <span class="chips" aria-label="Evidence">
                    <ToolChip v-for="t in evidence(p).tools" :key="t" :tool="t" />
                    <span v-if="evidence(p).rule" class="chip">Rule</span>
                  </span>
                </td>
                <td data-label="Connection"><span class="conn-name" :title="p.connection">{{ p.connection }}</span></td>
                <td data-label="Last seen" class="right">
                  <span class="mono">{{ p.last_seen }}</span>
                  <span class="mono since">since {{ p.first_seen }}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="panel-foot">
          <AppPagination :total="list.data.value.total" :page="page" :limit="PAGE" noun="attack path" @change="navigate({ page: $event })" />
        </div>
      </template>
    </section>
  </template>
</template>

<style scoped>
.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.path-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.path-link {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  text-decoration: underline;
  text-decoration-color: var(--border-control);
  text-underline-offset: 3px;
}

.path-link:hover {
  color: var(--link);
  text-decoration-color: currentcolor;
}

.summary {
  font-size: 12px;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-6);
  margin-top: var(--s-4);
}

.paths-table td {
  white-space: nowrap;
}

/* The path column takes what the others leave; it and the category may wrap. */
.paths-table td.path-cell {
  width: 100%;
  white-space: normal;
}

.paths-table td.category {
  white-space: normal;
  min-width: 140px;
}

.conn-name {
  display: inline-block;
  max-width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  vertical-align: bottom;
}

.since {
  display: block;
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
}

.through {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  align-self: flex-end;
  height: 32px;
}

.chip-x {
  display: inline-grid;
  place-items: center;
  width: 20px;
  height: 20px;
  padding: 0;
  border: 0;
  border-radius: 4px;
  background: none;
  color: var(--text-2);
  cursor: pointer;
}

.chip-x:hover {
  color: var(--text);
  background: var(--surface-active);
}
</style>
