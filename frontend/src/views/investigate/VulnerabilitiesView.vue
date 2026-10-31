<script setup lang="ts">
/**
 * Investigate -> Vulnerabilities (ADR-0042, amended 2026-10-31): the CVEs each provider's own
 * scanner reports (AWS Inspector on AWS), in one read-only list, apart from Misconfigurations.
 * As there, every filter, the order, the view and the page live in the URL
 * (vulnerabilityFilters.ts), and the resource sheet links here with ?resource= and a CVE's
 * own link with ?finding=.
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
import { int } from '@/format'
import { PROVIDERS, type Provider } from '@/providers'
import { SEVERITIES, SEVERITY_LABEL, type Severity } from '@/views/overview/severity'
import ExploitMark from './ExploitMark.vue'
import FindingDetail from './FindingDetail.vue'
import { type Muted, type Order, parseFinding, parseOrder, parsePage } from './findingFilters'
import { type FindingState, regionLabel, uidTail } from './labels'
import { epssPercent, packageLine } from './vulnerability'
import {
  type Fix,
  type VulnerabilityFilters,
  type VulnerabilityView,
  cveFilters,
  cveLabel,
  cveSubline,
  emptyVulnerabilityFilters,
  isVulnerabilityFiltered,
  parseVulnerabilityFilters,
  parseVulnerabilityView,
  vulnerabilityApiFilters,
  vulnerabilityFiltersToQuery,
  vulnerabilitySecondaryCount,
  vulnerabilityViewToQuery,
} from './vulnerabilityFilters'

const PAGE = 20

const route = useRoute()
const router = useRouter()

const filters = computed(() => parseVulnerabilityFilters(route.query))
const order = computed(() => parseOrder(route.query))
// One CVE's own link (?finding=): it shows alone, expanded; the filters do not apply.
const single = computed(() => parseFinding(route.query))
const view = computed<VulnerabilityView>(() => (single.value != null ? 'list' : parseVulnerabilityView(route.query)))

function navigate(next: VulnerabilityFilters, how: 'push' | 'replace' = 'push'): void {
  const sort = order.value === 'severity' ? undefined : order.value
  void router[how]({ query: { ...vulnerabilityFiltersToQuery(next), order: sort, view: vulnerabilityViewToQuery(view.value) } })
}

function set<K extends keyof VulnerabilityFilters>(key: K, value: VulnerabilityFilters[K]): void {
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
onBeforeUnmount(() => window.clearTimeout(typing))

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const resourceId = computed(() => filters.value.resource)
const resource = useResource(
  async () => (resourceId.value == null ? null : await unwrap(api.GET('/api/v1/resources/{resource_id}', { params: { path: { resource_id: resourceId.value } } }))),
  { watch: [resourceId] },
)

// The options that come from the data follow the chosen connections.
const connectionKey = computed(() => filters.value.connection.join(','))
const facets = useResource(() => unwrap(api.GET('/api/v1/vulnerabilities/facets', { params: { query: { connection_id: filters.value.connection } } })), {
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
    const next = { ...f, type: keep(f.type, data.resource_types), region: keep(f.region, data.regions) }
    if (JSON.stringify(next) !== JSON.stringify(f)) navigate(next, 'replace')
  },
)

const severityOptions: MultiOption[] = SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))
// GCP and OCI are offered, marked, so the filter reads the same once their scanners are in.
const providerOptions: MultiOption[] = PROVIDERS.map((p) => ({ value: p.id, label: p.name, note: p.covered ? undefined : 'not covered' }))
const connectionOptions = computed<MultiOption[]>(() => (connections.data.value ?? []).map((c) => ({ value: String(c.id), label: c.name })))
const mono = (values: string[] | undefined, label: (v: string) => string = (v) => v): MultiOption[] =>
  (values ?? []).map((v) => ({ value: v, label: label(v), mono: true }))
const typeOptions = computed(() => mono(facets.data.value?.resource_types))
const regionOptions = computed(() => mono(facets.data.value?.regions, regionLabel))
const MUTED_CHOICES: { value: Muted; label: string }[] = [
  { value: 'any', label: 'Show' },
  { value: 'hide', label: 'Hide' },
  { value: 'only', label: 'Only' },
]
const FIX_CHOICES: { value: Fix; label: string }[] = [
  { value: 'any', label: 'Any' },
  { value: 'available', label: 'Available' },
  { value: 'none', label: 'None yet' },
]

const more = ref(vulnerabilitySecondaryCount(filters.value) > 0)
const moreCount = computed(() => vulnerabilitySecondaryCount(filters.value))
watch(moreCount, (n) => {
  if (n > 0) more.value = true
})

const items = shallowRef<Schemas['FindingOut'][]>([])
const groups = shallowRef<Schemas['FindingGroupOut'][]>([])
// The view the rows on screen were loaded for: until a switch has loaded, the old rows stay.
const shown = ref<VulnerabilityView>(view.value)
const rows = computed(() => (shown.value === 'cves' ? groups.value.length : items.value.length))
const total = ref(0)
const capped = ref(false)
const dataThrough = ref<string | null>(null)
const loaded = ref(false)
const page = ref(parsePage(route.query))
const filtered = computed(() => isVulnerabilityFiltered(filters.value))
const table = ref<HTMLElement | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
const open = ref<Set<number>>(new Set())
let generation = 0

const requestKey = (target: number): string => JSON.stringify([vulnerabilityApiFilters(filters.value), order.value, target, single.value, view.value])
let loadedKey = ''

// The CVE of its own link, with the scanner's text: its details row needs no second request.
const singleDetail = shallowRef<Schemas['FindingDetail'] | null>(null)

async function loadOne(id: number, mine: number): Promise<void> {
  const one = await unwrap(api.GET('/api/v1/findings/{finding_id}', { params: { path: { finding_id: id } } }))
  if (mine !== generation) return
  singleDetail.value = one
  items.value = [one]
  shown.value = 'list'
  total.value = 1
  capped.value = false
  dataThrough.value = one.last_seen
  page.value = 1
  loaded.value = true
  open.value = new Set([one.id])
  loadedKey = requestKey(1)
}

async function load(target: number, how: 'push' | 'replace' = 'replace'): Promise<void> {
  const mine = ++generation
  loading.value = true
  error.value = null
  try {
    if (single.value != null) {
      await loadOne(single.value, mine)
      return
    }
    const query = { limit: PAGE, offset: (target - 1) * PAGE, order: order.value, ...vulnerabilityApiFilters(filters.value) }
    const byCve = view.value === 'cves'
    const result = byCve
      ? { ...(await unwrap(api.GET('/api/v1/vulnerabilities/groups', { params: { query } }))), total_capped: false }
      : await unwrap(api.GET('/api/v1/vulnerabilities', { params: { query } }))
    if (mine !== generation) return
    const last = Math.max(1, Math.ceil(result.total / PAGE))
    if (target > last) {
      void load(last) // the list shrank: show its last page
      return
    }
    if (byCve) {
      groups.value = result.items as Schemas['FindingGroupOut'][]
      items.value = []
    } else {
      items.value = result.items as Schemas['FindingOut'][]
      groups.value = []
    }
    shown.value = byCve ? 'cves' : 'list'
    total.value = result.total
    capped.value = result.total_capped
    dataThrough.value = result.data_through ?? null
    page.value = target
    loaded.value = true
    open.value = new Set()
    loadedKey = requestKey(target)
    const pageParam = target > 1 ? String(target) : undefined
    if (route.query.page !== pageParam) void router[how]({ query: { ...route.query, page: pageParam } })
  } catch (err) {
    if (mine === generation) {
      error.value =
        single.value != null && err instanceof ApiError && err.status === 404
          ? 'This vulnerability does not exist. Its link may be from another installation.'
          : err instanceof ApiError
            ? err.message
            : 'Vulnerabilities did not load.'
    }
  } finally {
    if (mine === generation) loading.value = false
  }
}

void load(page.value)
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

function setOrder(next: Order): void {
  void router.push({ query: { ...vulnerabilityFiltersToQuery(filters.value), order: next === 'severity' ? undefined : next, view: vulnerabilityViewToQuery(view.value) } })
}

function setView(next: VulnerabilityView): void {
  if (next === view.value) return
  void router.push({ query: { ...vulnerabilityFiltersToQuery(filters.value), order: route.query.order, view: vulnerabilityViewToQuery(next) } })
}

/** A CVE's group opens the list filtered to it. */
function openGroup(g: Schemas['FindingGroupOut']): void {
  void router.push({ query: { ...vulnerabilityFiltersToQuery(cveFilters(filters.value, g)), order: route.query.order } })
}

function onGroupClick(event: MouseEvent, g: Schemas['FindingGroupOut']): void {
  if ((event.target as Element).closest('a, button, input, select, label, summary')) return
  if (window.getSelection()?.toString()) return
  openGroup(g)
}

function sortBySeverity(): void {
  setOrder(order.value === 'severity' ? 'severity_asc' : 'severity')
}

function toggleLastSeen(): void {
  setOrder(order.value === 'last_seen_desc' ? 'last_seen_asc' : 'last_seen_desc')
}

function toggle(id: number): void {
  const next = new Set(open.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  open.value = next
}

/** A click anywhere on a row opens or closes its details, as the chevron does; a click on a
 * control in the row, or one that ends a text selection, is left alone. */
function onRowClick(event: MouseEvent, id: number): void {
  if ((event.target as Element).closest('a, button, input, select, label, summary')) return
  if (window.getSelection()?.toString()) return
  toggle(id)
}

function clearFilters(): void {
  window.clearTimeout(typing)
  search.value = ''
  navigate(emptyVulnerabilityFilters())
}

/** The row's lead: the CVE, or a code vulnerability's title. */
function lead(v: Schemas['FindingOut']): string {
  return v.vulnerability?.vulnerability_id ?? v.title
}

function isNew(v: Schemas['FindingOut']): boolean {
  return v.state === 'open' && v.first_seen === v.last_seen
}

const ORDER_NOTE: Record<Order, string> = {
  severity: 'Worst first.',
  severity_asc: 'Least severe first.',
  last_seen_desc: 'Most recently seen first.',
  last_seen_asc: 'Least recently seen first.',
}
const GROUP_ORDER_NOTE: Record<Order, string> = {
  severity: 'Worst first, then the most findings.',
  severity_asc: 'Least severe first.',
  last_seen_desc: 'Most recently seen first.',
  last_seen_asc: 'Least recently seen first.',
}
const VIEWS: { value: VulnerabilityView; label: string }[] = [
  { value: 'list', label: 'List' },
  { value: 'cves', label: 'By CVE' },
]

const resourceChip = computed(() => {
  const r = resource.data.value
  return r ? (r.name ?? r.native_id) : `#${resourceId.value}`
})
const noData = computed(() => loaded.value && dataThrough.value == null)
</script>

<template>
  <PageHeader title="Vulnerabilities">
    <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
    <template v-else-if="loaded">No scan yet</template>
  </PageHeader>

  <AlertBanner v-if="single != null" kind="info">
    Showing one vulnerability from its link.
    <template #action><RouterLink class="btn btn-secondary btn-sm" :to="{ name: 'vulnerabilities' }">Show all vulnerabilities</RouterLink></template>
  </AlertBanner>
  <FilterBar v-else label="Filter vulnerabilities" :active="filtered" @clear="clearFilters">
    <span v-if="resourceId" class="filter-chip" :title="resource.data.value?.resource_uid">
      Resource: <span class="mono">{{ resourceChip }}</span>
      <button type="button" class="icon-btn chip-x" aria-label="Remove resource filter" @click="set('resource', null)">
        <AppIcon name="cross" :size="14" :stroke="2.2" />
      </button>
    </span>
    <span v-if="filters.check.length" class="filter-chip" :title="filters.check.join(', ')">
      CVE: <span class="mono">{{ filters.check.map(cveLabel).join(', ') }}</span>
      <button type="button" class="icon-btn chip-x" aria-label="Remove CVE filter" @click="set('check', [])">
        <AppIcon name="cross" :size="14" :stroke="2.2" />
      </button>
    </span>
    <div class="field search">
      <label class="lbl" for="v-q">Search</label>
      <span class="search-wrap">
        <AppIcon name="search" :size="16" class="search-icon" />
        <input id="v-q" v-model="search" class="input" type="search" placeholder="Search by CVE, package or resource" maxlength="200" autocomplete="off">
      </span>
    </div>
    <MultiSelect id="v-sev" label="Severity" :options="severityOptions" :model-value="filters.severity" @update:model-value="set('severity', $event as Severity[])" />
    <div class="field">
      <label class="lbl" for="v-state">State</label>
      <select id="v-state" class="select" :value="filters.state" @change="set('state', ($event.target as HTMLSelectElement).value as FindingState)">
        <option value="open">Open</option>
        <option value="reopened">Reopened</option>
        <option value="resolved">Resolved</option>
        <option value="accepted_risk">Accepted risk</option>
      </select>
    </div>
    <MultiSelect
      id="v-conn"
      label="Connection"
      :options="connectionOptions"
      :status="connections.error.value ? 'error' : connections.data.value ? 'ready' : 'loading'"
      :model-value="filters.connection.map(String)"
      @update:model-value="set('connection', $event.map(Number))"
    />
    <MultiSelect id="v-provider" label="Provider" :options="providerOptions" :model-value="filters.provider" @update:model-value="set('provider', $event as Provider[])" />
    <div class="field">
      <span id="v-fix" class="lbl">Fix</span>
      <div class="segmented" role="group" aria-labelledby="v-fix">
        <button v-for="c in FIX_CHOICES" :key="c.value" type="button" :aria-pressed="filters.fix === c.value" @click="set('fix', c.value)">{{ c.label }}</button>
      </div>
    </div>
    <label class="check inline-check">
      <input type="checkbox" :checked="filters.exploitable" @change="set('exploitable', ($event.target as HTMLInputElement).checked)">
      Public exploit
    </label>
    <button type="button" class="btn btn-secondary more-btn" :aria-expanded="more" aria-controls="v-more" @click="more = !more">
      More filters<template v-if="moreCount"> · {{ moreCount }}</template>
      <AppIcon name="chevron" :size="16" :stroke="2" class="more-chev" />
    </button>
    <template #after>
      <div v-show="more" id="v-more" class="more-row">
        <MultiSelect id="v-type" label="Resource type" :options="typeOptions" :status="facetStatus" :model-value="filters.type" @update:model-value="set('type', $event)" />
        <MultiSelect id="v-region" label="Region" :options="regionOptions" :status="facetStatus" :model-value="filters.region" @update:model-value="set('region', $event)" />
        <div class="field">
          <span id="v-muted" class="lbl">Suppressed</span>
          <div class="segmented" role="group" aria-labelledby="v-muted">
            <button v-for="m in MUTED_CHOICES" :key="m.value" type="button" :aria-pressed="filters.muted === m.value" @click="set('muted', m.value)">{{ m.label }}</button>
          </div>
        </div>
        <label class="check inline-check">
          <input type="checkbox" :checked="filters.new" @change="set('new', ($event.target as HTMLInputElement).checked)">
          New in latest scan
        </label>
      </div>
    </template>
  </FilterBar>

  <section class="card panel" aria-labelledby="vulns-h">
    <div class="panel-h view-h">
      <div class="titles">
        <h2 id="vulns-h" class="h2">{{ shown === 'cves' ? 'CVEs with findings' : 'Vulnerabilities by resource' }}</h2>
        <span v-if="single != null" class="cap">One vulnerability, from its own link. Read-only.</span>
        <span v-else-if="shown === 'cves'" class="cap">{{ GROUP_ORDER_NOTE[order] }} Read-only.</span>
        <span v-else class="cap">{{ ORDER_NOTE[order] }} Read-only.</span>
      </div>
      <div v-if="single == null" class="segmented" role="group" aria-label="View">
        <button v-for="v in VIEWS" :key="v.value" type="button" :aria-pressed="view === v.value" @click="setView(v.value)">{{ v.label }}</button>
      </div>
    </div>

    <div v-if="error" class="panel-body">
      <AlertBanner kind="fail">
        Vulnerabilities didn't load: {{ error }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="load(page)">Retry</button></template>
      </AlertBanner>
    </div>
    <div v-else-if="!loaded" aria-busy="true" class="panel-body loading"><div v-for="n in 5" :key="n" class="skeleton sk-44"></div></div>
    <EmptyState v-else-if="noData" icon="bug" title="No vulnerabilities yet." text="They appear after a Vulnerabilities scan is ingested: each provider's own scanner (AWS Inspector on AWS).">
      <RouterLink class="btn btn-ghost" :to="{ name: 'schedules' }">Go to Schedules</RouterLink>
    </EmptyState>
    <EmptyState v-else-if="rows === 0 && filtered" icon="info" :title="shown === 'cves' ? 'No CVEs match these filters.' : 'No vulnerabilities match these filters.'">
      <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
    </EmptyState>
    <EmptyState v-else-if="rows === 0" icon="check" title="No open vulnerabilities." text="Every scanned resource is clean, or its vulnerabilities were resolved." />
    <div v-else-if="shown === 'cves'" ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="vulns-h" :aria-busy="loading">
      <table class="table stackable stack-narrow dense vulns-table">
        <thead>
          <tr>
            <SortHeader
              label="Severity"
              :direction="order === 'severity' ? 'desc' : order === 'severity_asc' ? 'asc' : null"
              desc-text="worst first"
              asc-text="least severe first"
              @toggle="sortBySeverity"
            /><th scope="col">CVE</th><th scope="col" class="right">Findings</th><th scope="col" class="right">Accounts</th>
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
          <tr v-for="g in groups" :key="g.check_id" class="row" @click="onGroupClick($event, g)">
            <td data-label="Severity"><SeverityTag :severity="g.severity" /></td>
            <td data-label="CVE" class="lead-cell">
              <button type="button" class="lead group-link" :class="{ mono: !g.check_id.startsWith('code:') }" :aria-label="`Show the ${int(g.findings)} finding${g.findings === 1 ? '' : 's'} of ${cveLabel(g.check_id)}`" @click="openGroup(g)">{{ cveLabel(g.check_id) }}</button>
              <span v-if="cveSubline(g.check_id, g.title)" class="sub" :title="g.title">{{ cveSubline(g.check_id, g.title) }}</span>
            </td>
            <td data-label="Findings" class="right mono">{{ int(g.findings) }}</td>
            <td data-label="Accounts" class="right mono">{{ int(g.connections) }}</td>
            <td data-label="Last seen" class="right mono">{{ g.last_seen }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="vulns-h" :aria-busy="loading">
      <table class="table stackable stack-narrow dense vulns-table">
        <thead>
          <tr>
            <SortHeader
              label="Severity"
              :direction="order === 'severity' ? 'desc' : order === 'severity_asc' ? 'asc' : null"
              desc-text="worst first"
              asc-text="least severe first"
              @toggle="sortBySeverity"
            /><th scope="col">Vulnerability</th><th scope="col">Resource</th><th scope="col">Connection</th><th scope="col">State</th>
            <SortHeader
              label="Last seen"
              class="right"
              :direction="order === 'last_seen_desc' ? 'desc' : order === 'last_seen_asc' ? 'asc' : null"
              desc-text="newest first"
              asc-text="oldest first"
              @toggle="toggleLastSeen"
            /><th scope="col"><span class="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="v in items" :key="v.id">
            <tr class="row" :class="{ expanded: open.has(v.id) }" @click="onRowClick($event, v.id)">
              <td data-label="Severity"><SeverityTag :severity="v.severity" /></td>
              <!-- The CVE leads; the package and its fix, a public exploit and EPSS follow. -->
              <td data-label="Vulnerability" class="lead-cell">
                <span class="lead" :class="{ mono: v.vulnerability?.vulnerability_id }" :title="v.title">{{ lead(v) }}</span>
                <span class="meta">
                  <span v-if="v.vulnerability" class="mono package">{{ packageLine(v.vulnerability) }}</span>
                  <ExploitMark v-if="v.vulnerability?.exploit_available" />
                  <span v-if="epssPercent(v.vulnerability?.epss_score)" class="mono epss">EPSS {{ epssPercent(v.vulnerability?.epss_score) }}</span>
                </span>
              </td>
              <td data-label="Resource" class="resource">
                <span class="mono" :title="v.resource_uid">{{ v.resource_name ?? uidTail(v.resource_uid) }}</span>
                <span v-if="v.resource_id == null" class="cap">Not in inventory</span>
              </td>
              <td data-label="Connection">
                <span class="conn"><ProviderTag :provider="v.provider" /><span class="conn-name">{{ v.connection }}</span></span>
                <span class="mono region">{{ regionLabel(v.region) }}</span>
              </td>
              <td data-label="State">
                <span class="states">
                  <StatusBadge :status="v.state" />
                  <span v-if="v.muted" class="chip">Suppressed</span>
                  <span v-if="isNew(v)" class="chip">New</span>
                </span>
              </td>
              <td data-label="Last seen" class="right mono">{{ v.last_seen }}</td>
              <td data-label="">
                <button type="button" class="icon-btn chev" :aria-expanded="open.has(v.id)" :aria-label="`${open.has(v.id) ? 'Hide' : 'Show'} details of ${lead(v)}`" @click="toggle(v.id)">
                  <AppIcon name="chevron" :size="16" :stroke="2" />
                </button>
              </td>
            </tr>
            <tr v-if="open.has(v.id)" class="detail">
              <td colspan="7">
                <FindingDetail :finding="v" :preloaded="single != null ? singleDetail : null" :own-link="single == null" />
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
    <div v-if="rows && single == null" class="panel-foot">
      <AppPagination :total="total" :capped="capped" :page="page" :limit="PAGE" :noun="shown === 'cves' ? 'CVE' : undefined" @change="goTo" />
    </div>
  </section>
</template>

<style scoped>
.strong {
  color: var(--text);
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

.filter-chip {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  height: 32px;
  margin-bottom: var(--s-4);
  padding: 0 var(--s-4) 0 var(--s-10);
  border: 1px solid var(--border-control);
  border-radius: var(--r-control);
  background: var(--surface-raised);
  font-size: 13px;
  max-width: 320px;
}

.filter-chip .mono {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chip-x {
  width: 24px;
  height: 24px;
}

/* The panel header holds the view toggle on its right; it wraps under the titles. */
.view-h {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: var(--s-12);
}

.lead {
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  font-weight: 500;
  color: var(--text);
  overflow-wrap: anywhere;
}

/* The second line: one line on a wide panel, clamped, so it never sets the table's width. */
.sub,
.package {
  display: -webkit-box;
  min-width: 0;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 1;
  line-clamp: 1;
  font-size: 12px;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

.meta {
  display: flex;
  align-items: center;
  flex-wrap: nowrap;
  gap: var(--s-6);
  margin-top: 3px;
}

.meta > :not(.package) {
  flex-shrink: 0;
}

.epss {
  font-size: 11px;
  color: var(--text-3);
}

.group-link {
  padding: 0;
  border: 0;
  background: none;
  font: inherit;
  font-weight: 500;
  text-align: left;
  color: var(--text);
  text-decoration: underline;
  text-decoration-color: var(--border-control);
  text-underline-offset: 3px;
  cursor: pointer;
}

.group-link.mono {
  font-family: var(--font-mono);
}

.group-link:hover {
  color: var(--link);
  text-decoration-color: currentcolor;
}

.region {
  display: block;
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
}

.resource .mono {
  display: block;
  font-size: 12px;
  max-width: 260px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.states {
  display: inline-flex;
  gap: var(--s-6);
  align-items: center;
  flex-wrap: wrap;
}

.chev :deep(svg) {
  transition: transform var(--ease);
}

.chev[aria-expanded='true'] :deep(svg) {
  transform: rotate(90deg);
}

.vulns-table tr.row {
  cursor: pointer;
}

.vulns-table tr.row.expanded > td {
  background: var(--surface-raised);
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
}

.table tr.detail > td,
.table tr.detail:hover > td {
  background: var(--tile);
}

.vulns-table tr.detail > td {
  padding: 0;
}

.vulns-table td {
  white-space: nowrap;
}

.vulns-table td.lead-cell,
.vulns-table tr.detail > td {
  white-space: normal;
}

/* The vulnerability column takes what the others leave. */
.vulns-table td.lead-cell {
  width: 100%;
  min-width: 200px;
}

/* Stacked rows (a narrow panel): the details take the whole row, the second line wraps. */
@container (max-width: 900px) {
  .vulns-table tr.detail > td {
    display: block;
  }

  .resource .mono {
    max-width: none;
  }

  .meta {
    flex-wrap: wrap;
  }

  .sub,
  .package {
    -webkit-line-clamp: 2;
    line-clamp: 2;
  }
}
</style>
