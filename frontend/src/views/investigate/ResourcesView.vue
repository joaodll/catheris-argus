<script setup lang="ts">
/**
 * Investigate -> Resources (docs/ui/screens.md, E8): Steampipe's inventory, read-only. The open
 * resource sheet lives in the URL (?open=), so a link to it works and Back closes it.
 */
import { computed, nextTick, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import FilterBar from '@/components/FilterBar.vue'
import PageHeader from '@/components/PageHeader.vue'
import ProviderTag from '@/components/ProviderTag.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import SortHeader from '@/components/SortHeader.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useResource } from '@/composables/useResource'
import ExploitMark from './ExploitMark.vue'
import { fromSelect, regionLabel, typesByService } from './labels'
import ResourceSheet from './ResourceSheet.vue'

type Order = 'name_asc' | 'name_desc' | 'last_seen_desc' | 'last_seen_asc'
// Open Inspector CVEs (ADR-0042): any, critical or high, or with a public exploit.
type Vulnerabilities = 'any' | 'high' | 'exploitable'
const VULNERABILITY_OPTIONS: { value: Vulnerabilities; label: string }[] = [
  { value: 'any', label: 'Any open vulnerability' },
  { value: 'high', label: 'Critical or high' },
  { value: 'exploitable', label: 'Public exploit' },
]
const PAGE = 20

const route = useRoute()
const router = useRouter()

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
// A link may arrive filtered (the Resource map's "See all in Resources": ?type=&connection=).
const linkedConnection = Number(route.query.connection)
const linkedType = typeof route.query.type === 'string' && route.query.type ? route.query.type : null
const connectionId = ref<number | null>(Number.isInteger(linkedConnection) && linkedConnection > 0 ? linkedConnection : null)
const rtype = ref<string | null>(linkedType)
if (route.query.type !== undefined || route.query.connection !== undefined) {
  void router.replace({ query: { ...route.query, type: undefined, connection: undefined } })
}
const region = ref<string | null>(null)
const vulnerabilities = ref<Vulnerabilities | null>(null)
const includeDeleted = ref(false)
const search = ref('') // what is typed
const query = ref('') // what is searched, 300 ms after typing stops
let typing: number | undefined
watch(search, (value) => {
  window.clearTimeout(typing)
  typing = window.setTimeout(() => (query.value = value.trim()), 300)
})

const facets = useResource(() => unwrap(api.GET('/api/v1/resources/facets', { params: { query: { connection_id: connectionId.value } } })), {
  watch: [connectionId],
})
const typeGroups = computed(() => typesByService(facets.data.value?.types ?? []))

const resources = shallowRef<Schemas['ResourceRow'][]>([])
const total = ref(0)
const capped = ref(false)
const dataThrough = ref<string | null>(null)
const loaded = ref(false)
const page = ref(1)
const order = ref<Order>('name_asc')
const filtered = computed(() =>
  Boolean(connectionId.value || rtype.value || region.value || vulnerabilities.value || query.value || includeDeleted.value),
)
const table = ref<HTMLElement | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
let generation = 0

async function load(target: number): Promise<void> {
  const mine = ++generation
  loading.value = true
  error.value = null
  try {
    const result = await unwrap(
      api.GET('/api/v1/resources', {
        params: {
          query: {
            limit: PAGE,
            offset: (target - 1) * PAGE,
            order: order.value,
            connection_id: connectionId.value,
            type: rtype.value,
            region: region.value,
            q: query.value || null,
            include_deleted: includeDeleted.value,
            vulnerabilities: vulnerabilities.value,
          },
        },
      }),
    )
    if (mine !== generation) return
    const last = Math.max(1, Math.ceil(result.total / PAGE))
    if (target > last) {
      // The page no longer exists (the list shrank): show the last one.
      void load(last)
      return
    }
    resources.value = result.items
    total.value = result.total
    capped.value = result.total_capped
    dataThrough.value = result.data_through ?? null
    page.value = target
    loaded.value = true
  } catch (err) {
    if (mine === generation) error.value = err instanceof ApiError ? err.message : 'Resources did not load.'
  } finally {
    if (mine === generation) loading.value = false
  }
}

// A filter or the order changes the list: back to page 1.
watch([connectionId, rtype, region, vulnerabilities, query, includeDeleted, order], () => void load(1), { immediate: true })
// Type and region lists follow the connection; a value it no longer has is dropped.
watch(
  () => facets.data.value,
  (data) => {
    if (!data) return
    if (rtype.value && !data.types.includes(rtype.value)) rtype.value = null
    if (region.value && !data.regions.includes(region.value)) region.value = null
  },
)

async function goTo(target: number): Promise<void> {
  await load(target)
  await nextTick()
  table.value?.focus() // the new rows are announced
}

function toggleName(): void {
  order.value = order.value === 'name_asc' ? 'name_desc' : 'name_asc'
}

function toggleLastSeen(): void {
  order.value = order.value === 'last_seen_desc' ? 'last_seen_asc' : 'last_seen_desc'
}

function clearFilters(): void {
  window.clearTimeout(typing)
  connectionId.value = null
  rtype.value = null
  region.value = null
  vulnerabilities.value = null
  includeDeleted.value = false
  search.value = ''
  query.value = ''
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
</script>

<template>
  <PageHeader title="Resources">
    <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
    <template v-else-if="loaded">No scan yet</template>
  </PageHeader>

  <FilterBar label="Filter resources" :active="filtered" @clear="clearFilters">
    <div class="field search">
      <label class="lbl" for="r-q">Search</label>
      <span class="search-wrap">
        <AppIcon name="search" :size="16" class="search-icon" />
        <input id="r-q" v-model="search" class="input" type="search" placeholder="Search by name, id or ARN" maxlength="200" autocomplete="off">
      </span>
    </div>
    <div class="field">
      <label class="lbl" for="r-conn">Connection</label>
      <select id="r-conn" class="select" :value="connectionId ?? ''" @change="connectionId = Number(fromSelect(($event.target as HTMLSelectElement).value)) || null">
        <option value="">All connections</option>
        <option v-for="c in connections.data.value ?? []" :key="c.id" :value="c.id">{{ c.name }}</option>
      </select>
    </div>
    <div class="field">
      <label class="lbl" for="r-type">Type</label>
      <select id="r-type" class="select mono" :value="rtype ?? ''" @change="rtype = fromSelect(($event.target as HTMLSelectElement).value)">
        <option value="">All types</option>
        <optgroup v-for="g in typeGroups" :key="g.service" :label="g.service">
          <option v-for="t in g.types" :key="t" :value="t">{{ t }}</option>
        </optgroup>
      </select>
    </div>
    <div class="field">
      <label class="lbl" for="r-region">Region</label>
      <select id="r-region" class="select" :value="region ?? ''" @change="region = fromSelect(($event.target as HTMLSelectElement).value)">
        <option value="">All regions</option>
        <option v-for="r in facets.data.value?.regions ?? []" :key="r" :value="r">{{ regionLabel(r) }}</option>
      </select>
    </div>
    <div class="field">
      <label class="lbl" for="r-vuln">Vulnerabilities</label>
      <select
        id="r-vuln"
        class="select"
        :value="vulnerabilities ?? ''"
        @change="vulnerabilities = fromSelect(($event.target as HTMLSelectElement).value) as Vulnerabilities | null"
      >
        <option value="">All resources</option>
        <option v-for="o in VULNERABILITY_OPTIONS" :key="o.value" :value="o.value">{{ o.label }}</option>
      </select>
    </div>
    <label class="check">
      <input v-model="includeDeleted" type="checkbox">
      Include deleted
    </label>
  </FilterBar>

  <!-- The Platform's list panel: a header bar, the table edge to edge, a footer bar. -->
  <section class="card panel" aria-labelledby="resources-h">
    <div class="panel-h">
      <div class="titles">
        <h2 id="resources-h" class="h2">Inventory</h2>
        <span class="cap">{{ includeDeleted ? 'Deleted resources included.' : 'Resources in the latest inventory.' }} Read-only.</span>
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
            /><th scope="col">Connection</th><th scope="col">VPC</th><th scope="col" class="right">Open findings</th><th scope="col" class="right">Vulnerabilities</th>
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
            <td data-label="Open findings" class="right">
              <span v-if="r.open_findings > 0" class="count">
                <SeverityTag v-if="r.worst_severity" :severity="r.worst_severity" compact />
                <span class="mono">{{ r.open_findings }}</span>
              </span>
              <span v-else class="mono soft">0</span>
            </td>
            <td data-label="Vulnerabilities" class="right">
              <span v-if="r.vulnerabilities == null" class="soft" title="Inspector does not cover this resource">—</span>
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
                  title="Inspector does not scan this resource; open it for the reason"
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
