<script setup lang="ts">
/**
 * Investigate -> Resources (docs/ui/screens.md, E8): Steampipe's inventory, read-only. Every
 * filter, the order and the page live in the URL (resourceFilters.ts, 2026-11-06), as on
 * Misconfigurations and Vulnerabilities, so a link reproduces a list. The open resource sheet
 * lives there too (?open=), so a link to it works and Back closes it. It opens on a Summary
 * (owner's decision 2026-11-06), the bare screen only: any list parameter, the sheet's
 * included, opens the list (summary/summaryTab.ts).
 */
import { computed, nextTick, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import FilterBar from '@/components/FilterBar.vue'
import MultiSelect, { type MultiOption } from '@/components/MultiSelect.vue'
import PageHeader from '@/components/PageHeader.vue'
import ProviderTag from '@/components/ProviderTag.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import SortHeader from '@/components/SortHeader.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useResource } from '@/composables/useResource'
import ExploitMark from './ExploitMark.vue'
import { parsePage } from './findingFilters'
import { fromSelect, regionLabel } from './labels'
import {
  type MisconfigurationLevel,
  type ResourceFilters,
  type ResourceOrder,
  type VulnerabilityLevel,
  emptyResourceFilters,
  isResourceFiltered,
  parseResourceFilters,
  parseResourceOrder,
  resourceApiFilters,
  resourceFiltersToQuery,
  resourceSecondaryCount,
} from './resourceFilters'
import ResourceSheet from './ResourceSheet.vue'
import InvestigateTabs from './summary/InvestigateTabs.vue'
import ResourceSummary from './summary/ResourceSummary.vue'
import { type Tab, parseTab, summaryConnection } from './summary/summaryTab'

const VULNERABILITY_OPTIONS: { value: VulnerabilityLevel; label: string }[] = [
  { value: 'any', label: 'Any open vulnerability' },
  { value: 'high', label: 'Critical or high' },
  { value: 'exploitable', label: 'Public exploit' },
]
const MISCONFIGURATION_OPTIONS: { value: MisconfigurationLevel; label: string }[] = [
  { value: 'any', label: 'Any open misconfiguration' },
  { value: 'high', label: 'Critical or high' },
]
const PAGE = 20

const route = useRoute()
const router = useRouter()
const filters = computed(() => parseResourceFilters(route.query))
const order = computed(() => parseResourceOrder(route.query))
// Summary | List: the bare screen opens the summary, any list parameter the list.
const tab = computed<Tab>(() => parseTab(route.query))
// The summary's account: the list's connection when it names exactly one.
const summaryAccount = computed(() => summaryConnection(filters.value.connection))

/** A new filter set: a history entry (typing in the search box replaces it), page 1. The tab is
 * written out, so clearing every filter keeps the list. */
function navigate(next: ResourceFilters, how: 'push' | 'replace' = 'push'): void {
  const sort = order.value === 'name_asc' ? undefined : order.value
  void router[how]({ query: { ...resourceFiltersToQuery(next), order: sort, tab: tab.value } })
}

/** Summary keeps only its account; List opens with that account as its connection filter. */
function setTab(next: Tab): void {
  if (next === tab.value) return
  const account = summaryAccount.value ? String(summaryAccount.value) : undefined
  void router.push({ query: { tab: next, connection: account } })
}

function selectAccount(id: number): void {
  void router.push({ query: { tab: 'summary', connection: id ? String(id) : undefined } })
}

function set<K extends keyof ResourceFilters>(key: K, value: ResourceFilters[K]): void {
  navigate({ ...filters.value, [key]: value })
}

const search = ref(filters.value.q) // what is typed; searched 300 ms after typing stops
let typing: number | undefined
watch(search, (value) => {
  window.clearTimeout(typing)
  typing = window.setTimeout(() => {
    if (value.trim() !== filters.value.q) navigate({ ...filters.value, q: value.trim() }, 'replace')
  }, 300)
})
watch(
  () => filters.value.q,
  (q) => {
    if (q !== search.value.trim()) search.value = q
  },
)

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
// The options that come from the data follow the chosen connections.
const connectionKey = computed(() => filters.value.connection.join(','))
const facets = useResource(() => unwrap(api.GET('/api/v1/resources/facets', { params: { query: { connection_id: filters.value.connection } } })), {
  watch: [connectionKey],
})
const facetStatus = computed(() => (facets.error.value ? 'error' : facets.data.value ? 'ready' : 'loading'))
// A chosen value the data no longer offers is dropped.
watch(
  () => facets.data.value,
  (data) => {
    if (!data) return
    const f = filters.value
    const keep = (values: string[], offered: string[]): string[] => values.filter((v) => offered.includes(v))
    const next = { ...f, type: keep(f.type, data.types), region: keep(f.region, data.regions) }
    if (JSON.stringify(next) !== JSON.stringify(f)) navigate(next, 'replace')
  },
)
const connectionOptions = computed<MultiOption[]>(() => (connections.data.value ?? []).map((c) => ({ value: String(c.id), label: c.name })))
const typeOptions = computed<MultiOption[]>(() => (facets.data.value?.types ?? []).map((t) => ({ value: t, label: t, mono: true })))
const regionOptions = computed<MultiOption[]>(() => (facets.data.value?.regions ?? []).map((r) => ({ value: r, label: regionLabel(r), mono: true })))

const more = ref(resourceSecondaryCount(filters.value) > 0)
const moreCount = computed(() => resourceSecondaryCount(filters.value))
watch(moreCount, (n) => {
  if (n > 0) more.value = true
})

const resources = shallowRef<Schemas['ResourceRow'][]>([])
const total = ref(0)
const capped = ref(false)
const dataThrough = ref<string | null>(null)
const loaded = ref(false)
const page = ref(parsePage(route.query))
const filtered = computed(() => isResourceFiltered(filters.value))
const table = ref<HTMLElement | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
let generation = 0
const requestKey = (target: number): string => JSON.stringify([resourceApiFilters(filters.value), order.value, target, tab.value])
let loadedKey = ''

async function load(target: number, how: 'push' | 'replace' = 'replace'): Promise<void> {
  const mine = ++generation
  if (tab.value !== 'list') {
    loading.value = false // the summary loads its own numbers; the list waits for its tab
    return
  }
  loading.value = true
  error.value = null
  try {
    const result = await unwrap(
      api.GET('/api/v1/resources', {
        params: { query: { limit: PAGE, offset: (target - 1) * PAGE, order: order.value, ...resourceApiFilters(filters.value) } },
      }),
    )
    if (mine !== generation) return
    const last = Math.max(1, Math.ceil(result.total / PAGE))
    if (target > last) {
      void load(last) // the list shrank: show its last page
      return
    }
    resources.value = result.items
    total.value = result.total
    capped.value = result.total_capped
    dataThrough.value = result.data_through ?? null
    page.value = target
    loaded.value = true
    loadedKey = requestKey(target)
    const pageParam = target > 1 ? String(target) : undefined
    if (route.query.page !== pageParam) void router[how]({ query: { ...route.query, page: pageParam } })
  } catch (err) {
    if (mine === generation) error.value = err instanceof ApiError ? err.message : 'Resources did not load.'
  } finally {
    if (mine === generation) loading.value = false
  }
}

void load(page.value)
// A filter, the order or the page changes in the URL (a click, Back, a link): load it. Opening
// or closing the sheet changes neither, so the list stays as it is.
watch(
  () => requestKey(parsePage(route.query)),
  (key) => {
    if (key !== loadedKey) void load(parsePage(route.query))
  },
)

async function goTo(target: number): Promise<void> {
  await load(target, 'push')
  await nextTick()
  table.value?.focus() // the new rows are announced
}

function setOrder(next: ResourceOrder): void {
  void router.push({ query: { ...resourceFiltersToQuery(filters.value), order: next === 'name_asc' ? undefined : next, tab: 'list' } })
}

function toggleName(): void {
  setOrder(order.value === 'name_asc' ? 'name_desc' : 'name_asc')
}

function toggleLastSeen(): void {
  setOrder(order.value === 'last_seen_desc' ? 'last_seen_asc' : 'last_seen_desc')
}

function clearFilters(): void {
  window.clearTimeout(typing)
  search.value = ''
  navigate(emptyResourceFilters())
}

function label(r: Schemas['ResourceRow']): string {
  return r.name ?? r.native_id
}

// The resource sheet.
const openId = computed(() => {
  const value = Number(route.query.open)
  return Number.isInteger(value) && value > 0 ? value : null
})
const openTitle = computed(() => {
  const row = resources.value.find((r) => r.id === openId.value)
  return row ? label(row) : 'Resource'
})
function closeSheet(): void {
  void router.replace({ query: { ...route.query, open: undefined }, hash: '' })
}
function connectionName(id: number): string {
  return connections.data.value?.find((c) => c.id === id)?.name ?? `Connection ${id}`
}
// An open sheet puts the resource's name in front of the page title.
const pageTitle = document.title
watch(
  [openId, openTitle],
  ([id, name]) => {
    document.title = id == null ? pageTitle : `${name} · ${pageTitle}`
  },
  { immediate: true },
)
// Leaving the page needs no reset: the router sets the next page's title.
onBeforeUnmount(() => window.clearTimeout(typing))

const noData = computed(() => loaded.value && dataThrough.value == null)
const removedOnly = computed(() => Boolean(filters.value.removedFrom || filters.value.removedTo))
const inventoryNote = computed(() =>
  removedOnly.value ? 'Removed resources only.' : filters.value.includeDeleted ? 'Deleted resources included.' : 'Resources in the latest inventory.',
)
</script>

<template>
  <PageHeader title="Resources">
    <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
    <template v-else-if="loaded">No scan yet</template>
  </PageHeader>

  <InvestigateTabs :model-value="tab" label="Resources views" id-prefix="res" @update:model-value="setTab" />
  <div v-if="tab === 'summary'" id="res-summary" role="tabpanel" aria-labelledby="res-tab-summary" class="tabpanel">
    <ResourceSummary :connection-id="summaryAccount" :connections="connections.data.value" @select-connection="selectAccount" />
  </div>
  <div v-else id="res-list" role="tabpanel" aria-labelledby="res-tab-list" class="tabpanel">
    <FilterBar label="Filter resources" :active="filtered" @clear="clearFilters">
      <div class="field search">
        <label class="lbl" for="r-q">Search</label>
        <span class="search-wrap">
          <AppIcon name="search" :size="16" class="search-icon" />
          <input id="r-q" v-model="search" class="input" type="search" placeholder="Search by name, id or ARN" maxlength="200" autocomplete="off">
        </span>
      </div>
      <MultiSelect
        id="r-conn"
        label="Connection"
        :options="connectionOptions"
        :status="connections.error.value ? 'error' : connections.data.value ? 'ready' : 'loading'"
        :model-value="filters.connection.map(String)"
        @update:model-value="set('connection', $event.map(Number))"
      />
      <MultiSelect id="r-type" label="Type" :options="typeOptions" :status="facetStatus" :model-value="filters.type" @update:model-value="set('type', $event)" />
      <MultiSelect id="r-region" label="Region" :options="regionOptions" :status="facetStatus" :model-value="filters.region" @update:model-value="set('region', $event)" />
      <div class="field">
        <label class="lbl" for="r-vuln">Vulnerabilities</label>
        <select
          id="r-vuln"
          class="select"
          :value="filters.vulnerabilities ?? ''"
          @change="set('vulnerabilities', fromSelect(($event.target as HTMLSelectElement).value) as VulnerabilityLevel | null)"
        >
          <option value="">All resources</option>
          <option v-for="o in VULNERABILITY_OPTIONS" :key="o.value" :value="o.value">{{ o.label }}</option>
        </select>
      </div>
      <button type="button" class="btn btn-secondary more-btn" :aria-expanded="more" aria-controls="r-more" @click="more = !more">
        More filters<template v-if="moreCount"> · {{ moreCount }}</template>
        <AppIcon name="chevron" :size="16" :stroke="2" class="more-chev" />
      </button>
      <template #after>
        <div v-show="more" id="r-more" class="more-row">
          <div class="field">
            <label class="lbl" for="r-misconf">Misconfigurations</label>
            <select
              id="r-misconf"
              class="select"
              :value="filters.misconfigurations ?? ''"
              @change="set('misconfigurations', fromSelect(($event.target as HTMLSelectElement).value) as MisconfigurationLevel | null)"
            >
              <option value="">All resources</option>
              <option v-for="o in MISCONFIGURATION_OPTIONS" :key="o.value" :value="o.value">{{ o.label }}</option>
            </select>
          </div>
          <label class="check inline-check" title="An open misconfiguration that Argus's rules confirm is reachable from the internet">
            <input type="checkbox" :checked="filters.internet" @change="set('internet', ($event.target as HTMLInputElement).checked)">
            Internet reachable
          </label>
          <label class="check inline-check" title="Leave out parts, settings and links (rules, attachments, versions): what the Overview counts as assets">
            <input type="checkbox" :checked="filters.assets" @change="set('assets', ($event.target as HTMLInputElement).checked)">
            Assets only
          </label>
          <fieldset class="field days">
            <legend class="lbl">First seen</legend>
            <span class="dates">
              <label class="sr-only" for="r-seen-from">First seen on or after</label>
              <input id="r-seen-from" class="input date" type="date" :value="filters.firstSeenFrom" :max="filters.firstSeenTo || undefined" @change="set('firstSeenFrom', ($event.target as HTMLInputElement).value)">
              <span aria-hidden="true">to</span>
              <label class="sr-only" for="r-seen-to">First seen on or before</label>
              <input id="r-seen-to" class="input date" type="date" :value="filters.firstSeenTo" :min="filters.firstSeenFrom || undefined" @change="set('firstSeenTo', ($event.target as HTMLInputElement).value)">
            </span>
          </fieldset>
          <fieldset class="field days">
            <legend class="lbl">Removed</legend>
            <span class="dates">
              <label class="sr-only" for="r-removed-from">Removed on or after</label>
              <input id="r-removed-from" class="input date" type="date" :value="filters.removedFrom" :max="filters.removedTo || undefined" @change="set('removedFrom', ($event.target as HTMLInputElement).value)">
              <span aria-hidden="true">to</span>
              <label class="sr-only" for="r-removed-to">Removed on or before</label>
              <input id="r-removed-to" class="input date" type="date" :value="filters.removedTo" :min="filters.removedFrom || undefined" @change="set('removedTo', ($event.target as HTMLInputElement).value)">
            </span>
          </fieldset>
          <label class="check inline-check">
            <input type="checkbox" :checked="filters.includeDeleted" @change="set('includeDeleted', ($event.target as HTMLInputElement).checked)">
            Include deleted
          </label>
        </div>
      </template>
    </FilterBar>

    <!-- The Platform's list panel: a header bar, the table edge to edge, a footer bar. -->
    <section class="card panel" aria-labelledby="resources-h">
      <div class="panel-h">
        <div class="titles">
          <h2 id="resources-h" class="h2">Inventory</h2>
          <span class="cap">{{ inventoryNote }} Read-only.</span>
        </div>
      </div>

      <div v-if="error" class="panel-body">
        <AlertBanner kind="fail">
          Resources didn't load: {{ error }}
          <template #action><button type="button" class="btn btn-secondary btn-sm" @click="load(page)">Retry</button></template>
        </AlertBanner>
      </div>
      <div v-else-if="!loaded" aria-busy="true" class="panel-body loading"><div v-for="n in 5" :key="n" class="skeleton sk-48"></div></div>
      <div v-else-if="noData" class="panel-body">
        <EmptyState icon="stack" title="No resources yet." text="The inventory appears after a Steampipe scan is ingested.">
          <RouterLink class="btn btn-ghost" :to="{ name: 'schedules' }">Go to Schedules</RouterLink>
        </EmptyState>
      </div>
      <div v-else-if="resources.length === 0 && filtered" class="panel-body">
        <EmptyState icon="info" title="No resources match these filters.">
          <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
        </EmptyState>
      </div>
      <div v-else-if="resources.length === 0" class="panel-body">
        <EmptyState icon="stack" title="No resources in the latest inventory." />
      </div>
      <div v-else ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="resources-h" :aria-busy="loading">
        <table class="table stackable stack-narrow dense resources-table">
          <thead>
            <tr>
              <SortHeader
                label="Name"
                :direction="order === 'name_asc' ? 'asc' : order === 'name_desc' ? 'desc' : null"
                desc-text="Z to A"
                asc-text="A to Z"
                @toggle="toggleName"
              /><th scope="col">Connection</th><th scope="col">VPC</th><th scope="col" class="right">Misconfigurations</th><th scope="col" class="right">Vulnerabilities</th>
              <SortHeader
                label="Last seen"
                class="right"
                :direction="order === 'last_seen_desc' ? 'desc' : order === 'last_seen_asc' ? 'asc' : null"
                desc-text="newest first"
                asc-text="oldest first"
                @toggle="toggleLastSeen"
              />
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in resources" :key="r.id">
              <td data-label="Name" class="name">
                <span class="name-cell">
                  <!-- A link, so it opens in a new tab too (?open= works on direct load). -->
                  <RouterLink
                    class="btn btn-ghost btn-sm open"
                    :class="{ mono: r.name == null }"
                    :title="r.resource_uid"
                    :to="{ query: { ...route.query, open: String(r.id) } }"
                  >
                    {{ label(r) }}
                  </RouterLink>
                  <span v-if="r.deleted_on" :title="`Deleted on ${r.deleted_on}`"><StatusBadge status="deleted" /></span>
                </span>
                <span class="mono sub">{{ r.type }}</span>
              </td>
              <td data-label="Connection">
                <span class="conn"><ProviderTag :provider="r.provider" /><span class="conn-name">{{ connectionName(r.connection_id) }}</span></span>
                <span class="mono sub">{{ regionLabel(r.region) }}</span>
              </td>
              <td data-label="VPC" class="mono" :class="{ soft: !r.vpc_id }">{{ r.vpc_id ?? '—' }}</td>
              <td data-label="Misconfigurations" class="right">
                <span v-if="r.open_findings > 0" class="count">
                  <SeverityTag v-if="r.worst_severity" :severity="r.worst_severity" compact />
                  <span class="mono">{{ r.open_findings }}</span>
                </span>
                <span v-else class="mono soft">0</span>
              </td>
              <td data-label="Vulnerabilities" class="right">
                <span v-if="r.vulnerabilities == null" class="soft" title="No vulnerability scanner covers this resource">—</span>
                <template v-else>
                  <span v-if="r.vulnerabilities.open > 0" class="count">
                    <SeverityTag v-if="r.vulnerabilities.worst" :severity="r.vulnerabilities.worst" compact />
                    <span class="mono">{{ r.vulnerabilities.open }}</span>
                    <ExploitMark v-if="r.vulnerabilities.exploitable > 0" :count="r.vulnerabilities.exploitable" />
                  </span>
                  <span v-else-if="r.vulnerabilities.scanned" class="mono soft">0</span>
                  <span
                    v-if="!r.vulnerabilities.scanned"
                    class="soft not-scanned"
                    :class="{ sub: r.vulnerabilities.open > 0 }"
                    title="The vulnerability scanner does not scan this resource; open it for the reason"
                  >Not scanned</span>
                </template>
              </td>
              <td data-label="Last seen" class="right mono">{{ r.last_seen }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="resources.length" class="panel-foot">
        <AppPagination :total="total" :capped="capped" :page="page" :limit="PAGE" @change="goTo" />
      </div>
    </section>
  </div>

  <ResourceSheet
    v-if="openId != null"
    :resource-id="openId"
    :fallback-title="openTitle"
    :connection-name="connectionName"
    :at="route.hash === '#from-internet' ? 'from-internet' : null"
    @close="closeSheet"
  />
</template>

<style scoped>
.strong {
  color: var(--text);
}

.tabpanel {
  display: flex;
  flex-direction: column;
  gap: var(--s-16); /* as the shell's main column, which held these blocks before the tabs */
}

.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.search {
  flex: 1 1 240px;
  max-width: 420px;
}

.days {
  margin: 0;
  padding: 0;
  border: 0;
}

.dates {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  font-size: 13px;
  color: var(--text-2);
}

.date {
  width: 150px;
}

.more-row {
  flex: 1 0 100%;
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--s-12) var(--s-16);
  padding-top: var(--s-12);
  border-top: 1px solid var(--border);
}

.more-btn {
  gap: var(--s-6);
}

.more-chev {
  transform: rotate(90deg);
}

.more-btn[aria-expanded='true'] .more-chev {
  transform: rotate(-90deg);
}

.inline-check {
  min-height: var(--control-h);
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

.name-cell {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

/* The name opens the sheet: a real button, aligned with the cell's text. */
.open {
  max-width: 480px;
  padding: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  justify-content: flex-start;
}

/* A second line under a cell's value: the type under the name, the region under the connection. */
.sub {
  display: block;
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
  overflow-wrap: anywhere;
}

.conn {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
}

.conn-name {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.count {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
}

.soft {
  color: var(--text-3);
}

.not-scanned {
  font-size: 12px;
}

.resources-table td {
  white-space: nowrap;
}

/* The name column takes what the others leave; its type line may wrap. */
.resources-table td.name {
  width: 100%;
  white-space: normal;
}
</style>
