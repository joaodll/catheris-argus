<script setup lang="ts">
/**
 * Investigate -> Attack paths (ADR-0052; spec W6 Part A and its R2 delta §10): the stored routes,
 * one row per way in and kind of route (kind, entry), each with its worst targets, worst first.
 * Argus works routes out after each ingested scan (the worker, or the `paths` Job); this page
 * only reads what was stored. Every role sees it (owner, 2026-11-15). Filters, order and page
 * live in the URL (routeFilters.ts); ?route=<id> opens one route in place of the table.
 */
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import FilterBar from '@/components/FilterBar.vue'
import MultiSelect, { type MultiOption } from '@/components/MultiSelect.vue'
import PageHeader from '@/components/PageHeader.vue'
import MapTabs from '../map/MapTabs.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import SortHeader from '@/components/SortHeader.vue'
import { useResource } from '@/composables/useResource'
import { utc } from '@/format'
import { SEVERITIES, SEVERITY_LABEL, type Severity } from '@/views/overview/severity'
import { CLASS_LABEL, ROUTE_CLASSES, type RouteClass } from './routeClass'
import RouteClassBadge from './RouteClassBadge.vue'
import RouteDetail from './RouteDetail.vue'
import {
  type RouteFilters,
  type RouteOrder,
  isRouteFiltered,
  parsePage,
  parseRouteFilters,
  parseRouteId,
  parseRouteOrder,
  routeApiFilters,
  routeFiltersToQuery,
} from './routeFilters'
import { crossesLine, routeSubline, routeTitle, type Names } from './routeWords'

const PAGE = 50
const route = useRoute()
const router = useRouter()

const filters = computed(() => parseRouteFilters(route.query))
const order = computed(() => parseRouteOrder(route.query))
const page = computed(() => parsePage(route.query))
const routeId = computed(() => parseRouteId(route.query))

function navigate(next: { filters?: RouteFilters; order?: RouteOrder; page?: number }, how: 'push' | 'replace' = 'push'): void {
  const o = next.order ?? order.value
  const p = next.page ?? (next.filters || next.order ? 1 : page.value)
  void router[how]({
    query: {
      ...routeFiltersToQuery(next.filters ?? filters.value),
      order: o === 'severity' ? undefined : o,
      page: p > 1 ? String(p) : undefined,
    },
  })
}
function set<K extends keyof RouteFilters>(key: K, value: RouteFilters[K]): void {
  navigate({ filters: { ...filters.value, [key]: value } })
}
function clearFilters(): void {
  navigate({ filters: parseRouteFilters({}) })
}

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const names: Names = {
  connection: (id) => connections.data.value?.find((c) => c.id === id)?.name ?? `Connection ${id}`,
  ofAccount: (account) => connections.data.value?.find((c) => c.account_id === account)?.name ?? null,
}

const facets = useResource(
  () => {
    const f = routeApiFilters(filters.value)
    return unwrap(api.GET('/api/v1/attack-paths/facets', { params: { query: { state: f.state, connection_id: f.connection_id, crossing: f.crossing, through: f.through } } }))
  },
  { watch: [() => JSON.stringify([filters.value.state, filters.value.connection, filters.value.crossing, filters.value.through])] },
)
const facetStatus = computed(() => (facets.error.value ? 'error' : facets.data.value ? 'ready' : 'loading'))
const severityOptions: MultiOption[] = SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))
const kindOptions = computed<MultiOption[]>(() => Object.keys(facets.data.value?.kind ?? {}).map((k) => ({ value: k, label: facets.data.value?.kind_names[k] ?? k })))
// Strongest first, as a reader picks them; Latent last.
const confidenceOptions: MultiOption[] = [...ROUTE_CLASSES].reverse().map((c) => ({ value: c, label: CLASS_LABEL[c] }))
const latentHidden = computed(() => !filters.value.confidence.length && (facets.data.value?.cls.blocked ?? 0) > 0)

// The resource of a "Through" filter, by name.
const through = useResource(
  async () => {
    const id = filters.value.through
    if (id == null) return null
    return await unwrap(api.GET('/api/v1/resources/{resource_id}', { params: { path: { resource_id: id } } }))
  },
  { watch: [() => filters.value.through] },
)
const throughName = computed(() => {
  const r = through.data.value
  return r ? (r.name ?? r.native_id) : `resource ${filters.value.through}`
})

const list = useResource(
  async () => {
    if (routeId.value != null) return null
    return await unwrap(
      api.GET('/api/v1/attack-paths', {
        params: { query: { ...routeApiFilters(filters.value), order: order.value, limit: PAGE, offset: (page.value - 1) * PAGE } },
      }),
    )
  },
  { watch: [() => JSON.stringify([filters.value, order.value, page.value, routeId.value])] },
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
const filtered = computed(() => isRouteFiltered(filters.value))
const chosenConnection = computed(() => (filters.value.connection ? names.connection(filters.value.connection) : null))
const fixed = computed(() => filters.value.state === 'fixed')
const evaluation = computed(() => list.data.value?.evaluation ?? null)
const neverEvaluated = computed(() => evaluation.value != null && evaluation.value.evaluated_at == null)
const dataThrough = computed(() => list.data.value?.data_through ?? null)

// An open route puts its title in front of the page title.
const pageTitle = document.title
const openName = ref<string | null>(null)
watch(
  [routeId, openName],
  ([id, name]) => {
    document.title = id != null && name ? `${name} · ${pageTitle}` : pageTitle
  },
  { immediate: true },
)
</script>

<template>
  <!-- A route is a detail page: a breadcrumb back to the list, whose filters stay in the URL. -->
  <template v-if="routeId != null">
    <nav class="breadcrumb" aria-label="Breadcrumb">
      <RouterLink :to="{ query: { ...route.query, route: undefined, target: undefined } }"><AppIcon name="chevron" :size="13" :stroke="2.2" class="back-icon" />Attack paths</RouterLink>
      <span class="sep" aria-hidden="true">/</span>
      <span aria-current="page">{{ openName ?? 'Attack path' }}</span>
    </nav>
    <RouteDetail :route-id="routeId" :names="names" @loaded="openName = $event">
      <template #back>
        <RouterLink class="btn btn-secondary" :to="{ query: { ...route.query, route: undefined, target: undefined } }">← Attack paths</RouterLink>
      </template>
    </RouteDetail>
  </template>

  <template v-else>
    <PageHeader title="Map">
      <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
    </PageHeader>
    <MapTabs current="attack-paths" />
    <FilterBar :active="filtered" label="Filters" @clear="clearFilters">
      <MultiSelect id="ap-sev" label="Severity" :options="severityOptions" :model-value="filters.severity" @update:model-value="set('severity', $event as Severity[])" />
      <MultiSelect id="ap-kind" label="Kind" :options="kindOptions" :status="facetStatus" :model-value="filters.kind" @update:model-value="set('kind', $event)" />
      <MultiSelect id="ap-conf" label="Confidence" :options="confidenceOptions" :model-value="filters.confidence" @update:model-value="set('confidence', $event as RouteClass[])" />
      <div class="field">
        <label class="lbl" for="ap-conn">Connection</label>
        <select id="ap-conn" class="select" :value="filters.connection ?? ''" @change="set('connection', Number(($event.target as HTMLSelectElement).value) || null)">
          <option value="">All connections</option>
          <option v-for="c in connections.data.value ?? []" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </div>
      <label v-if="filters.connection" class="check">
        <input type="checkbox" :checked="filters.crossing" @change="set('crossing', ($event.target as HTMLInputElement).checked)">
        Include routes that cross it
      </label>
      <div class="field">
        <span id="ap-state" class="lbl">State</span>
        <div class="segmented" role="group" aria-labelledby="ap-state">
          <button type="button" :aria-pressed="filters.state === 'open'" @click="set('state', 'open')">Open</button>
          <button type="button" :aria-pressed="filters.state === 'fixed'" @click="set('state', 'fixed')">Fixed</button>
        </div>
      </div>
      <span v-if="filters.through != null" class="chip through">
        Through: {{ throughName }}
        <button type="button" class="chip-x" :aria-label="`Remove the filter Through: ${throughName}`" @click="set('through', null)"><AppIcon name="cross" :size="12" :stroke="2.4" /></button>
      </span>
    </FilterBar>

    <section class="card panel" aria-labelledby="ap-h">
      <div class="panel-h">
        <div class="titles">
          <h2 id="ap-h" class="h2">{{ fixed ? 'Fixed attack paths' : 'Open attack paths' }}</h2>
          <span class="cap">Worst first. One row per way in and kind of route, each with its worst targets. Each target is as sure as its weakest step; a row shows its surest target. Read-only.</span>
        </div>
      </div>

      <!-- §2.2, in this order: behind the scans, the last evaluation failed, latent routes hidden. -->
      <div v-if="evaluation?.behind && evaluation.evaluated_at" class="panel-body">
        <AlertBanner kind="info">
          Routes are behind the scans: they were worked out at {{ utc(evaluation.evaluated_at) }}, before scans ingested since. They update after the next evaluation.
          <template #action><button type="button" class="btn btn-secondary btn-sm" @click="list.reload">Refresh</button></template>
        </AlertBanner>
      </div>
      <div v-if="evaluation?.failed_at" class="panel-body">
        <AlertBanner kind="warn">
          The last route evaluation failed at {{ utc(evaluation.failed_at) }}.
          <template v-if="evaluation.evaluated_at">These are the routes from {{ utc(evaluation.evaluated_at) }}.</template>
          <template #action><RouterLink class="btn btn-secondary btn-sm" :to="{ name: 'runs' }">See Runs</RouterLink></template>
        </AlertBanner>
      </div>
      <div v-if="latentHidden" class="panel-body">
        <AlertBanner kind="info">
          Latent routes are hidden: Argus found a step closed, and they show what one change would open.
          <template #action><button type="button" class="btn btn-secondary btn-sm" @click="set('confidence', ['blocked'])">Show latent routes</button></template>
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
        <EmptyState v-if="neverEvaluated" icon="route" title="Routes haven't been worked out yet." text="Argus works them out after each ingested scan." />
        <EmptyState
          v-else-if="filters.connection && !dataThrough"
          icon="route"
          :title="`Not covered: neither Steampipe nor CloudFox has scanned ${chosenConnection}.`"
          text="Routes appear after a Steampipe or CloudFox scan of this connection is ingested."
        />
        <EmptyState v-else-if="filtered" icon="info" title="No attack paths match these filters.">
          <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
        </EmptyState>
        <EmptyState
          v-else
          icon="route"
          title="No open attack paths."
          text="After each ingested scan, Argus walks from every way in (the internet, an outside principal, a leaked credential) through the connections its rules and CloudFox found, and keeps each route that ends at something that matters."
        />
      </div>
      <template v-else>
        <div class="table-wrap table-fit">
          <table class="table stackable stack-narrow dense routes-table">
            <thead>
              <tr>
                <SortHeader label="Severity" :direction="order === 'severity' ? 'desc' : null" desc-text="worst first" asc-text="worst first" @toggle="navigate({ order: 'severity' })" />
                <th scope="col">Route</th>
                <th scope="col">Confidence</th>
                <th scope="col">Accounts</th>
                <SortHeader
                  :label="fixed ? 'Fixed' : 'Last seen'"
                  class="right"
                  :direction="order === 'last_seen' ? 'desc' : null"
                  desc-text="newest first"
                  asc-text="newest first"
                  @toggle="navigate({ order: 'last_seen' })"
                />
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in list.data.value.items" :key="r.id">
                <td data-label="Severity"><SeverityTag :severity="r.severity" /></td>
                <td data-label="Route" class="route-cell">
                  <RouterLink class="route-link" :title="routeTitle(r, names)" :to="{ query: { ...route.query, route: String(r.id) } }">{{ routeTitle(r, names) }}</RouterLink>
                  <span class="sub">{{ routeSubline(r, names) }}</span>
                </td>
                <td data-label="Confidence"><RouteClassBadge :cls="r.worst_class" /></td>
                <td data-label="Accounts" class="accounts">
                  <span class="conn-name" :title="names.connection(r.connection_id)">{{ names.connection(r.connection_id) }}</span>
                  <span v-if="crossesLine(r, names)" class="small" :title="crossesLine(r, names)!.title">{{ crossesLine(r, names)!.text }}</span>
                </td>
                <td :data-label="fixed ? 'Fixed' : 'Last seen'" class="right">
                  <span v-if="fixed" class="mono">Fixed {{ r.resolved_on }}</span>
                  <span v-else class="mono">{{ r.last_seen }}</span>
                  <span class="mono small">First seen {{ r.first_seen }}</span>
                  <span v-if="r.state === 'reopened'" class="reopened"><AppIcon name="reopen" :size="12" :stroke="2.2" />Reopened</span>
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

.route-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

/* The title wraps to two lines, then clamps; the whole title is in the link's title. */
.route-link {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  font-size: 13px;
  font-weight: 500;
  overflow-wrap: anywhere;
  color: var(--text);
  text-decoration: underline;
  text-decoration-color: var(--border-control);
  text-underline-offset: 3px;
}

.route-link:hover {
  color: var(--link);
  text-decoration-color: currentcolor;
}

.sub {
  font-size: 12px;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

.routes-table td {
  white-space: nowrap;
}

/* The route column takes what the others leave, and wraps. */
.routes-table td.route-cell {
  width: 100%;
  white-space: normal;
}

.conn-name,
.small {
  display: block;
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.small {
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
}

.reopened {
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-2);
}

.right .mono {
  display: block;
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

@media (max-width: 899px) {
  .conn-name,
  .small {
    max-width: none;
    white-space: normal;
    overflow-wrap: anywhere;
  }
}
</style>
