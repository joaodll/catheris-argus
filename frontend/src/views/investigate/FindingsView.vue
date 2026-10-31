<script setup lang="ts">
/**
 * Investigate -> Findings (docs/ui/screens.md, E7): Prowler checks and CloudFox attacker findings
 * in one read-only list. Every filter, the order and the page live in the URL (findingFilters.ts),
 * so a filtered list can be bookmarked or shared, Back restores it, and the resource sheet links
 * here with ?resource=.
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
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { int } from '@/format'
import { PROVIDERS, type Provider } from '@/providers'
import { SEVERITIES, SEVERITY_LABEL, type Severity } from '@/views/overview/severity'
import {
  type FindingFilters,
  type Muted,
  type Order,
  type Result,
  type Tool,
  type View,
  apiFilters,
  categoryLabel,
  emptyFilters,
  filtersToQuery,
  groupFilters,
  isFiltered,
  keptChecks,
  parseFilters,
  parseFinding,
  parseOrder,
  parsePage,
  parseView,
  secondaryCount,
  viewToQuery,
} from './findingFilters'
import FindingDetail from './FindingDetail.vue'
import { type FindingState, findingLine, regionLabel, uidTail } from './labels'
import ReachBadge from './ReachBadge.vue'
import { FINDING_REACHES, FINDING_REACH_LABEL, type FindingReach } from './reachReason'

const PAGE = 20

const route = useRoute()
const router = useRouter()

const filters = computed(() => parseFilters(route.query))
const order = computed(() => parseOrder(route.query))
// One finding's own link (?finding=): it shows alone, expanded; the filters do not apply.
const single = computed(() => parseFinding(route.query))
// List, or by check (?view=checks): a finding's own link is always the list.
const view = computed<View>(() => (single.value != null ? 'list' : parseView(route.query)))

/** A new filter set: a history entry (typing in the search box replaces it), page 1. */
function navigate(next: FindingFilters, how: 'push' | 'replace' = 'push'): void {
  const sort = order.value === 'severity' ? undefined : order.value
  void router[how]({ query: { ...filtersToQuery(next), order: sort, view: viewToQuery(view.value) } })
}

function set<K extends keyof FindingFilters>(key: K, value: FindingFilters[K]): void {
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
// Back, Clear filters or a link change the search: the box follows.
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
const facets = useResource(() => unwrap(api.GET('/api/v1/findings/facets', { params: { query: { connection_id: filters.value.connection } } })), {
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
    const next = {
      ...f,
      category: keep(f.category, data.categories),
      service: keep(f.service, data.services),
      type: keep(f.type, data.resource_types),
      check: keptChecks(f, data.checks.map((c) => c.check_id)),
      region: keep(f.region, data.regions),
    }
    if (JSON.stringify(next) !== JSON.stringify(f)) navigate(next, 'replace')
  },
)

const severityOptions: MultiOption[] = SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))
// GCP and OCI are offered, marked, so the filter reads the same once they are covered.
const providerOptions: MultiOption[] = PROVIDERS.map((p) => ({ value: p.id, label: p.name, note: p.covered ? undefined : 'not covered' }))
const toolOptions: MultiOption[] = [
  { value: 'prowler', label: 'Prowler' },
  { value: 'cloudfox', label: 'CloudFox' },
  { value: 'inspector', label: 'Inspector' },
]
const reachOptions: MultiOption[] = FINDING_REACHES.map((r) => ({ value: r, label: FINDING_REACH_LABEL[r] }))
const resultOptions: MultiOption[] = [
  { value: 'FAIL', label: 'Fail' },
  { value: 'MANUAL', label: 'Manual' },
]
const connectionOptions = computed<MultiOption[]>(() => (connections.data.value ?? []).map((c) => ({ value: String(c.id), label: c.name })))
const categoryOptions = computed<MultiOption[]>(() => (facets.data.value?.categories ?? []).map((c) => ({ value: c, label: categoryLabel(c) })))
const mono = (values: string[] | undefined, label: (v: string) => string = (v) => v): MultiOption[] =>
  (values ?? []).map((v) => ({ value: v, label: label(v), mono: true }))
const serviceOptions = computed(() => mono(facets.data.value?.services))
const typeOptions = computed(() => mono(facets.data.value?.resource_types))
const regionOptions = computed(() => mono(facets.data.value?.regions, regionLabel))
const checkOptions = computed<MultiOption[]>(() => {
  const seen = new Set<string>()
  const offered = (facets.data.value?.checks ?? [])
    .filter((c) => !seen.has(c.check_id) && seen.add(c.check_id))
    .map((c) => ({ value: c.check_id, label: c.check_id, mono: true, tool: c.tool }))
  // An Inspector check (a CVE) is not a facet: chosen from its group, it is offered too.
  const chosen = filters.value.check.filter((c) => !seen.has(c)).map((c) => ({ value: c, label: c, mono: true, tool: 'inspector' }))
  return [...chosen, ...offered]
})
const MUTED_CHOICES: { value: Muted; label: string }[] = [
  { value: 'any', label: 'Show' },
  { value: 'hide', label: 'Hide' },
  { value: 'only', label: 'Only' },
]

const more = ref(secondaryCount(filters.value) > 0)
const moreCount = computed(() => secondaryCount(filters.value))
watch(moreCount, (n) => {
  if (n > 0) more.value = true
})

const findings = shallowRef<Schemas['FindingOut'][]>([])
const groups = shallowRef<Schemas['FindingGroupOut'][]>([])
// The view the rows on screen were loaded for: until a switch has loaded, the old rows stay
// (never a flash of "No open findings.").
const shown = ref<View>(view.value)
const rows = computed(() => (shown.value === 'checks' ? groups.value.length : findings.value.length))
const total = ref(0)
const capped = ref(false)
const dataThrough = ref<string | null>(null)
const loaded = ref(false)
const page = ref(parsePage(route.query))
const filtered = computed(() => isFiltered(filters.value))
const table = ref<HTMLElement | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
const open = ref<Set<number>>(new Set())
let generation = 0

const requestKey = (target: number): string => JSON.stringify([apiFilters(filters.value), order.value, target, single.value, view.value])
let loadedKey = ''

// The finding of its own link, with the tool's text: its details row needs no second request.
const singleDetail = shallowRef<Schemas['FindingDetail'] | null>(null)

async function loadOne(id: number, mine: number): Promise<void> {
  const one = await unwrap(api.GET('/api/v1/findings/{finding_id}', { params: { path: { finding_id: id } } }))
  if (mine !== generation) return
  singleDetail.value = one
  findings.value = [one]
  shown.value = 'list'
  total.value = 1
  capped.value = false
  dataThrough.value = one.last_seen // the scan time this finding reflects
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
    const query = { limit: PAGE, offset: (target - 1) * PAGE, order: order.value, ...apiFilters(filters.value) }
    const byCheck = view.value === 'checks'
    const result = byCheck
      ? { ...(await unwrap(api.GET('/api/v1/findings/groups', { params: { query } }))), total_capped: false }
      : await unwrap(api.GET('/api/v1/findings', { params: { query } }))
    if (mine !== generation) return
    const last = Math.max(1, Math.ceil(result.total / PAGE))
    if (target > last) {
      // The page no longer exists (the list shrank): show the last one.
      void load(last)
      return
    }
    if (byCheck) {
      groups.value = result.items as Schemas['FindingGroupOut'][]
      findings.value = []
    } else {
      findings.value = result.items as Schemas['FindingOut'][]
      groups.value = []
    }
    shown.value = byCheck ? 'checks' : 'list'
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
          ? 'This finding does not exist. Its link may be from another installation.'
          : err instanceof ApiError
            ? err.message
            : 'Findings did not load.'
    }
  } finally {
    if (mine === generation) loading.value = false
  }
}

// The URL drives the list: the first load keeps its page; a filter or order change is page 1
// (navigate drops the page), and Back or Forward restores the page they held.
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
  void router.push({ query: { ...filtersToQuery(filters.value), order: next === 'severity' ? undefined : next, view: viewToQuery(view.value) } })
}

/** List or by check: the filters and the order stay, the page goes back to 1. */
function setView(next: View): void {
  if (next === view.value) return
  void router.push({ query: { ...filtersToQuery(filters.value), order: route.query.order, view: viewToQuery(next) } })
}

/** A check's group opens the list filtered to it (the Check and Tool filters show it). */
function openGroup(g: Schemas['FindingGroupOut']): void {
  void router.push({ query: { ...filtersToQuery(groupFilters(filters.value, g)), order: route.query.order } })
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

/** A click anywhere on a row opens or closes its details, as the chevron does (the chevron stays
 * the keyboard and screen reader control). A click on a link or control in the row, or one that
 * ends a text selection (copying a title or uid), is left alone. */
function onRowClick(event: MouseEvent, id: number): void {
  if ((event.target as Element).closest('a, button, input, select, label, summary')) return
  if (window.getSelection()?.toString()) return
  toggle(id)
}

function removeResource(): void {
  set('resource', null)
}

function clearFilters(): void {
  window.clearTimeout(typing)
  search.value = ''
  navigate(emptyFilters())
}

function resourceCell(f: Schemas['FindingOut']): string {
  return f.resource_name ?? uidTail(f.resource_uid)
}

function isNew(f: Schemas['FindingOut']): boolean {
  return f.state === 'open' && f.first_seen === f.last_seen
}

const ORDER_NOTE: Record<Order, string> = {
  severity: 'Worst first.',
  severity_asc: 'Least severe first.',
  last_seen_desc: 'Most recently seen first.',
  last_seen_asc: 'Least recently seen first.',
}

const resourceChip = computed(() => {
  const r = resource.data.value
  return r ? (r.name ?? r.native_id) : `#${resourceId.value}`
})
const noData = computed(() => loaded.value && dataThrough.value == null)
const GROUP_ORDER_NOTE: Record<Order, string> = {
  severity: 'Worst first, then the most findings.',
  severity_asc: 'Least severe first.',
  last_seen_desc: 'Most recently seen first.',
  last_seen_asc: 'Least recently seen first.',
}
const VIEWS: { value: View; label: string }[] = [
  { value: 'list', label: 'List' },
  { value: 'checks', label: 'By check' },
]
</script>

<template>
  <PageHeader title="Findings">
    <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
    <template v-else-if="loaded">No scan yet</template>
  </PageHeader>

  <AlertBanner v-if="single != null" kind="info">
    Showing one finding from its link.
    <template #action><RouterLink class="btn btn-secondary btn-sm" :to="{ name: 'findings' }">Show all findings</RouterLink></template>
  </AlertBanner>
  <FilterBar v-else label="Filter findings" :active="filtered" @clear="clearFilters">
    <span v-if="resourceId" class="filter-chip" :title="resource.data.value?.resource_uid">
      Resource: <span class="mono">{{ resourceChip }}</span>
      <button type="button" class="icon-btn chip-x" aria-label="Remove resource filter" @click="removeResource">
        <AppIcon name="cross" :size="14" :stroke="2.2" />
      </button>
    </span>
    <div class="field search">
      <label class="lbl" for="f-q">Search</label>
      <span class="search-wrap">
        <AppIcon name="search" :size="16" class="search-icon" />
        <input id="f-q" v-model="search" class="input" type="search" placeholder="Search by title, check or resource" maxlength="200" autocomplete="off">
      </span>
    </div>
    <MultiSelect
      id="f-sev"
      label="Severity"
      :options="severityOptions"
      :model-value="filters.severity"
      @update:model-value="set('severity', $event as Severity[])"
    />
    <div class="field">
      <label class="lbl" for="f-state">State</label>
      <select id="f-state" class="select" :value="filters.state" @change="set('state', ($event.target as HTMLSelectElement).value as FindingState)">
        <option value="open">Open</option>
        <option value="reopened">Reopened</option>
        <option value="resolved">Resolved</option>
        <option value="accepted_risk">Accepted risk</option>
      </select>
    </div>
    <MultiSelect
      id="f-conn"
      label="Connection"
      :options="connectionOptions"
      :status="connections.error.value ? 'error' : connections.data.value ? 'ready' : 'loading'"
      :model-value="filters.connection.map(String)"
      @update:model-value="set('connection', $event.map(Number))"
    />
    <MultiSelect
      id="f-provider"
      label="Provider"
      :options="providerOptions"
      :model-value="filters.provider"
      @update:model-value="set('provider', $event as Provider[])"
    />
    <MultiSelect id="f-tool" label="Tool" :options="toolOptions" :model-value="filters.tool" @update:model-value="set('tool', $event as Tool[])" />
    <MultiSelect
      id="f-cat"
      label="Category"
      :options="categoryOptions"
      :status="facetStatus"
      :model-value="filters.category"
      @update:model-value="set('category', $event)"
    />
    <button type="button" class="btn btn-secondary more-btn" :aria-expanded="more" aria-controls="f-more" @click="more = !more">
      More filters<template v-if="moreCount"> · {{ moreCount }}</template>
      <AppIcon name="chevron" :size="16" :stroke="2" class="more-chev" />
    </button>
    <template #after>
      <div v-show="more" id="f-more" class="more-row">
        <MultiSelect
          id="f-svc"
          label="Service"
          :options="serviceOptions"
          :status="facetStatus"
          :model-value="filters.service"
          @update:model-value="set('service', $event)"
        />
        <MultiSelect
          id="f-type"
          label="Resource type"
          :options="typeOptions"
          :status="facetStatus"
          :model-value="filters.type"
          @update:model-value="set('type', $event)"
        />
        <MultiSelect
          id="f-check"
          label="Check"
          :options="checkOptions"
          :status="facetStatus"
          :model-value="filters.check"
          @update:model-value="set('check', $event)"
        />
        <MultiSelect
          id="f-reach"
          label="Reach"
          :options="reachOptions"
          :model-value="filters.reach"
          @update:model-value="set('reach', $event as FindingReach[])"
        />
        <MultiSelect
          id="f-region"
          label="Region"
          :options="regionOptions"
          :status="facetStatus"
          :model-value="filters.region"
          @update:model-value="set('region', $event)"
        />
        <MultiSelect
          id="f-result"
          label="Result"
          :options="resultOptions"
          :model-value="filters.result"
          @update:model-value="set('result', $event as Result[])"
        />
        <div class="field">
          <span id="f-muted" class="lbl">Muted</span>
          <div class="segmented" role="group" aria-labelledby="f-muted">
            <button
              v-for="m in MUTED_CHOICES"
              :key="m.value"
              type="button"
              :aria-pressed="filters.muted === m.value"
              @click="set('muted', m.value)"
            >
              {{ m.label }}
            </button>
          </div>
        </div>
        <label class="check new-check">
          <input type="checkbox" :checked="filters.new" @change="set('new', ($event.target as HTMLInputElement).checked)">
          New in latest scan
        </label>
      </div>
    </template>
  </FilterBar>

  <!-- The Platform's list panel: a header bar, the table edge to edge, a footer bar. -->
  <section class="card panel" aria-labelledby="findings-h">
    <div class="panel-h view-h">
      <div class="titles">
        <h2 id="findings-h" class="h2">{{ shown === 'checks' ? 'Checks with findings' : 'Prowler, CloudFox and Inspector findings' }}</h2>
        <span v-if="single != null" class="cap">One finding, from its own link. Read-only.</span>
        <span v-else-if="shown === 'checks'" class="cap">{{ GROUP_ORDER_NOTE[order] }} Read-only.</span>
        <span v-else class="cap">{{ ORDER_NOTE[order] }} Read-only.</span>
      </div>
      <div v-if="single == null" class="segmented" role="group" aria-label="View">
        <button v-for="v in VIEWS" :key="v.value" type="button" :aria-pressed="view === v.value" @click="setView(v.value)">{{ v.label }}</button>
      </div>
    </div>

    <div v-if="error" class="panel-body">
      <AlertBanner kind="fail">
        Findings didn't load: {{ error }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="load(page)">Retry</button></template>
      </AlertBanner>
    </div>
    <div v-else-if="!loaded" aria-busy="true" class="panel-body loading"><div v-for="n in 5" :key="n" class="skeleton sk-44"></div></div>
    <EmptyState v-else-if="noData" icon="flag" title="No findings yet." text="Findings appear after a Prowler, CloudFox or Inspector scan is ingested.">
      <RouterLink class="btn btn-ghost" :to="{ name: 'schedules' }">Go to Schedules</RouterLink>
    </EmptyState>
    <EmptyState v-else-if="rows === 0 && filtered" icon="info" :title="shown === 'checks' ? 'No checks match these filters.' : 'No findings match these filters.'">
      <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
    </EmptyState>
    <EmptyState
      v-else-if="rows === 0"
      icon="check"
      title="No open findings."
      text="Every check that ran passed, or its findings were resolved."
    />
    <div v-else-if="shown === 'checks'" ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="findings-h" :aria-busy="loading">
      <table class="table stackable stack-narrow dense findings-table groups-table">
        <thead>
          <tr>
            <SortHeader
              label="Severity"
              :direction="order === 'severity' ? 'desc' : order === 'severity_asc' ? 'asc' : null"
              desc-text="worst first"
              asc-text="least severe first"
              @toggle="sortBySeverity"
            /><th scope="col">Check</th><th scope="col" class="right">Findings</th><th scope="col" class="right">Accounts</th>
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
          <tr v-for="g in groups" :key="`${g.tool}|${g.check_id}`" class="row" @click="onGroupClick($event, g)">
            <td data-label="Severity"><SeverityTag :severity="g.severity" /></td>
            <td data-label="Check" class="finding">
              <button type="button" class="title group-link" :title="g.title" :aria-label="`Show the ${int(g.findings)} findings of ${g.title}`" @click="openGroup(g)">{{ g.title }}</button>
              <span class="meta"><ToolChip :tool="g.tool" /><span class="mono check">{{ g.check_id }}</span></span>
            </td>
            <td data-label="Findings" class="right mono">{{ int(g.findings) }}</td>
            <td data-label="Accounts" class="right mono">{{ int(g.connections) }}</td>
            <td data-label="Last seen" class="right mono">{{ g.last_seen }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="findings-h" :aria-busy="loading">
      <table class="table stackable stack-narrow dense findings-table">
        <thead>
          <tr>
            <SortHeader
              label="Severity"
              :direction="order === 'severity' ? 'desc' : order === 'severity_asc' ? 'asc' : null"
              desc-text="worst first"
              asc-text="least severe first"
              @toggle="sortBySeverity"
            /><th scope="col">Finding</th><th scope="col">Resource</th><th scope="col">Connection</th><th scope="col">State</th>
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
          <template v-for="f in findings" :key="f.id">
            <tr class="row" :class="{ expanded: open.has(f.id) }" @click="onRowClick($event, f.id)">
              <td data-label="Severity"><SeverityTag :severity="f.severity" /></td>
              <!-- Two lines (2026-10-31 review): Prowler's result for this resource leads, the
                   check's title (its passing condition) follows; other tools keep their title. -->
              <td data-label="Finding" class="finding">
                <span class="title" :title="findingLine(f).lead">{{ findingLine(f).lead }}</span>
                <span class="meta">
                  <ToolChip :tool="f.tool" />
                  <span v-if="findingLine(f).check" class="check-title" :title="findingLine(f).check!">Check: {{ findingLine(f).check }}</span>
                  <ReachBadge :reach="f.reach" :reason="f.reach_reason" />
                </span>
              </td>
              <td data-label="Resource" class="resource">
                <span class="mono" :title="f.resource_uid">{{ resourceCell(f) }}</span>
                <span v-if="f.resource_id == null" class="cap">Not in inventory</span>
              </td>
              <td data-label="Connection">
                <span class="conn"><ProviderTag :provider="f.provider" /><span class="conn-name">{{ f.connection }}</span></span>
                <span class="mono region">{{ regionLabel(f.region) }}</span>
              </td>
              <td data-label="State">
                <span class="states">
                  <StatusBadge :status="f.state" />
                  <span v-if="f.muted" class="chip">Muted</span>
                  <span v-if="isNew(f)" class="chip">New</span>
                </span>
              </td>
              <td data-label="Last seen" class="right mono">{{ f.last_seen }}</td>
              <td data-label="">
                <button type="button" class="icon-btn chev" :aria-expanded="open.has(f.id)" :aria-label="`${open.has(f.id) ? 'Hide' : 'Show'} details of ${findingLine(f).lead}`" @click="toggle(f.id)">
                  <AppIcon name="chevron" :size="16" :stroke="2" />
                </button>
              </td>
            </tr>
            <tr v-if="open.has(f.id)" class="detail">
              <td colspan="7">
                <FindingDetail :finding="f" :preloaded="single != null ? singleDetail : null" :own-link="single == null" />
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
    <div v-if="rows && single == null" class="panel-foot">
      <AppPagination :total="total" :capped="capped" :page="page" :limit="PAGE" :noun="shown === 'checks' ? 'check' : undefined" @change="goTo" />
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

.new-check {
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

.finding {
  min-width: 200px;
}

.title {
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  font-weight: 500;
  color: var(--text);
}

.meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--s-6);
  margin-top: 3px;
}

.check {
  min-width: 0;
  font-size: 11px;
  color: var(--text-3);
  overflow-wrap: anywhere;
}

/* The check's title after the tool chip: one line, the whole title on hover. A clamp, not
   nowrap: an unbreakable line would set the table's minimum width and scroll it sideways. */
.check-title {
  display: -webkit-box;
  flex: 0 1 auto;
  min-width: 0;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 1;
  line-clamp: 1;
  font-size: 12px;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

/* A row's second line stays one line on a wide panel: the check's title shrinks between the
   tool chip and the reach badge. */
.finding .meta {
  flex-wrap: nowrap;
}

.finding .meta > :not(.check-title) {
  flex-shrink: 0;
}

/* The panel header holds the view toggle on its right; it wraps under the titles. */
.view-h {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: var(--s-12);
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

.findings-table tr.row {
  cursor: pointer;
}

.findings-table tr.row.expanded > td {
  background: var(--surface-raised);
}

.conn {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
}

.table tr.detail > td,
.table tr.detail:hover > td {
  background: var(--tile);
}

/* As on Runs: a finding's details stay within the visible width of the card (.table-fit is
   the container). */
.findings-table tr.detail > td {
  padding: 0;
}

.findings-table td {
  white-space: nowrap;
}

.findings-table td.finding,
.findings-table tr.detail > td {
  white-space: normal;
}

/* The title column takes what the others leave. */
.findings-table td.finding {
  width: 100%;
}

.conn-name {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Stacked rows (a narrow panel): the details take the whole row. */
@container (max-width: 900px) {
  .findings-table tr.detail > td {
    display: block;
  }

  .finding,
  .resource .mono {
    max-width: none;
  }

  .finding .meta {
    flex-wrap: wrap;
  }

  .check-title {
    -webkit-line-clamp: 2;
    line-clamp: 2;
  }
}
</style>
