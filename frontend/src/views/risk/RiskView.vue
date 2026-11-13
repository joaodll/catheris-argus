<script setup lang="ts">
/**
 * Risk (ADR-0049; spec in the palace, frontend/4180ca5e): the resources where facts from different
 * tools add up, worst first. The tiles and the By combination counts are stored counts
 * (GET /risk/summary); each one opens the list filtered to reproduce it. Every filter, the page
 * and the open resource sheet (?open=) live in the URL. The account picker is the list's
 * connection filter, so the tiles and the list always count the same accounts.
 */
import { computed, nextTick, ref, shallowRef, watch } from 'vue'
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
import { useResource } from '@/composables/useResource'
import { int } from '@/format'
import { PROVIDERS } from '@/providers'
import { parsePage } from '@/views/investigate/findingFilters'
import { typesByService } from '@/views/investigate/labels'
import ResourceSheet from '@/views/investigate/ResourceSheet.vue'
import SummaryHeader from '@/views/investigate/summary/SummaryHeader.vue'
import { SEVERITY_LABEL } from '@/views/overview/severity'
import { riskFacts } from './riskFacts'
import {
  COMBINATION_IDS,
  type CombinationId,
  type RiskFilters,
  TIERS,
  type Tier,
  emptyRiskFilters,
  isRiskFiltered,
  parseRiskFilters,
  riskApiFilters,
  riskFiltersToQuery,
  riskLink,
} from './riskFilters'

const PAGE = 20
const route = useRoute()
const router = useRouter()
const filters = computed(() => parseRiskFilters(route.query))
const account = computed(() => filters.value.connection ?? 0)

function navigate(next: RiskFilters): void {
  void router.push({ query: riskFiltersToQuery(next) })
}
function set<K extends keyof RiskFilters>(key: K, value: RiskFilters[K]): void {
  navigate({ ...filters.value, [key]: value })
}
function selectAccount(id: number): void {
  navigate({ ...filters.value, connection: id || null, type: [] })
}
function clearFilters(): void {
  navigate({ ...emptyRiskFilters(), connection: filters.value.connection })
}

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const combinations = useResource(() => unwrap(api.GET('/api/v1/risk/combinations')))
const summary = useResource(() => unwrap(api.GET('/api/v1/risk/summary', { params: { query: { connection_id: account.value } } })), {
  watch: [account],
})
const facets = useResource(
  () => unwrap(api.GET('/api/v1/risk/facets', { params: { query: { connection_id: filters.value.connection == null ? [] : [filters.value.connection] } } })),
  { watch: [account] },
)

const byId = computed(() => new Map((combinations.data.value ?? []).map((c) => [c.id, c])))
function title(id: CombinationId): string {
  return byId.value.get(id)?.title ?? id
}
function tierOf(id: CombinationId): Tier {
  return byId.value.get(id)?.tier ?? 'medium'
}

const tierOptions: MultiOption[] = TIERS.map((t) => ({ value: t, label: SEVERITY_LABEL[t] }))
const combinationOptions = computed<MultiOption[]>(() => COMBINATION_IDS.map((id) => ({ value: id, label: title(id) })))
const providerOptions: MultiOption[] = PROVIDERS.map((p) => ({ value: p.id, label: p.name, note: p.covered ? undefined : 'not covered' }))
const typeOptions = computed<MultiOption[]>(() =>
  typesByService(facets.data.value?.types ?? []).flatMap((g) => g.types.map((t) => ({ value: t, label: t, mono: true, group: g.service }))),
)
const facetStatus = computed(() => (facets.error.value ? 'error' : facets.data.value ? 'ready' : 'loading'))

// The tiles: one per tier, with the tier's most frequent combination under it.
const tiles = computed(() => {
  const s = summary.data.value
  return TIERS.map((tier) => {
    const count = s?.computed ? (s.tiers?.[tier] ?? 0) : null
    const top = s?.computed
      ? COMBINATION_IDS.filter((id) => tierOf(id) === tier && (s.combinations?.[id] ?? 0) > 0).sort(
          (a, b) => (s.combinations?.[b] ?? 0) - (s.combinations?.[a] ?? 0),
        )[0]
      : undefined
    return { tier, count, top }
  })
})

// The list.
const rows = shallowRef<Schemas['RiskRow'][]>([])
const total = ref(0)
const computedScope = ref(true)
const loaded = ref(false)
const loading = ref(false)
const error = ref<string | null>(null)
const page = ref(parsePage(route.query))
const table = ref<HTMLElement | null>(null)
let generation = 0
const requestKey = (target: number): string => JSON.stringify([riskApiFilters(filters.value), target])
let loadedKey = ''

async function load(target: number, how: 'push' | 'replace' = 'replace'): Promise<void> {
  const mine = ++generation
  loading.value = true
  error.value = null
  try {
    const result = await unwrap(api.GET('/api/v1/risk', { params: { query: { limit: PAGE, offset: (target - 1) * PAGE, ...riskApiFilters(filters.value) } } }))
    if (mine !== generation) return
    const last = Math.max(1, Math.ceil(result.total / PAGE))
    if (target > last) {
      void load(last)
      return
    }
    rows.value = result.items
    total.value = result.total
    computedScope.value = result.computed
    page.value = target
    loaded.value = true
    loadedKey = requestKey(target)
    const pageParam = target > 1 ? String(target) : undefined
    if (route.query.page !== pageParam) void router[how]({ query: { ...route.query, page: pageParam } })
  } catch (err) {
    if (mine === generation) error.value = err instanceof ApiError ? err.message : 'Risk did not load.'
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
  table.value?.focus()
}

function retry(): void {
  void load(page.value)
  void summary.reload()
}

function connectionName(id: number): string {
  return connections.data.value?.find((c) => c.id === id)?.name ?? `Connection ${id}`
}
function label(r: Schemas['RiskRow']): string {
  return r.name ?? `Resource ${r.resource_id}`
}

// The resource sheet.
const openId = computed(() => {
  const value = Number(route.query.open)
  return Number.isInteger(value) && value > 0 ? value : null
})
const openTitle = computed(() => {
  const row = rows.value.find((r) => r.resource_id === openId.value)
  return row ? label(row) : 'Resource'
})
function openQuery(id: number) {
  return { query: { ...route.query, open: String(id) } }
}
function closeSheet(): void {
  void router.replace({ query: { ...route.query, open: undefined }, hash: '' })
}

const filtered = computed(() => isRiskFiltered(filters.value))
const noConnections = computed(() => connections.data.value != null && connections.data.value.length === 0)
const dataThrough = computed(() => summary.data.value?.data_through ?? null)
</script>

<template>
  <PageHeader title="Risk">
    Resources where facts from different tools add up, worst first.
  </PageHeader>

  <div class="summary">
    <SummaryHeader
      id-prefix="risk"
      :connection-id="account"
      :connections="connections.data.value"
      :data-through="dataThrough"
      :loaded="summary.data.value != null"
      :legend="false"
      @select-connection="selectAccount"
    >
      Each row is one resource where two facts meet. Only facts on the resource itself count: an instance behind an internet-facing load
      balancer is not counted as open to the internet, because the load balancer is its door.
    </SummaryHeader>

    <AlertBanner v-if="summary.error.value" kind="fail">
      The counts didn't load: {{ summary.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="summary.reload()">Retry</button></template>
    </AlertBanner>
    <section v-else aria-label="Resources at risk by tier" class="stat-grid three">
      <template v-if="summary.data.value == null">
        <div v-for="n in 3" :key="n" class="stat-card skeleton" aria-busy="true"></div>
      </template>
      <div v-for="t in tiles" v-else :key="t.tier" class="stat-card tile" :style="{ '--tone': t.count ? `var(--sev-${t.tier})` : undefined }">
        <div class="stat-label"><span>{{ SEVERITY_LABEL[t.tier] }}</span></div>
        <b class="stat-value" :class="{ none: t.count == null }">{{ t.count == null ? '—' : int(t.count) }}</b>
        <span class="stat-sub">{{ t.count == null ? 'Not computed yet' : t.top ? title(t.top) : 'None' }}</span>
        <RouterLink
          v-if="t.count"
          class="drill-link"
          :to="riskLink({ connection: filters.connection, tier: [t.tier] })"
          :aria-label="`${SEVERITY_LABEL[t.tier]}: ${int(t.count)} resources. Show in list`"
        >
          Show in list<AppIcon name="chevron" :size="14" :stroke="2" />
        </RouterLink>
      </div>
    </section>

    <section class="card panel" aria-labelledby="risk-combos-h">
      <div class="panel-h"><h2 id="risk-combos-h" class="h2">By combination</h2></div>
      <ul class="combos">
        <li v-for="id in COMBINATION_IDS" :key="id" class="combo">
          <span class="combo-name">
            <SeverityTag :severity="tierOf(id)" compact />
            <span>
              <span class="combo-title">{{ title(id) }}</span>
              <span class="sub soft">{{ byId.get(id)?.description }}</span>
            </span>
          </span>
          <RouterLink
            v-if="summary.data.value?.computed"
            class="mono combo-count"
            :to="riskLink({ connection: filters.connection, combination: [id] })"
            :aria-label="`${title(id)}: ${int(summary.data.value.combinations?.[id] ?? 0)} resources. Show in list`"
          >
            {{ int(summary.data.value.combinations?.[id] ?? 0) }}
          </RouterLink>
          <span v-else class="mono soft combo-count">—</span>
        </li>
      </ul>
    </section>

    <FilterBar label="Filter resources at risk" :active="filtered" @clear="clearFilters">
      <MultiSelect id="risk-tier" label="Tier" :options="tierOptions" status="ready" :model-value="filters.tier" @update:model-value="set('tier', $event as Tier[])" />
      <MultiSelect
        id="risk-combo"
        label="Combination"
        :options="combinationOptions"
        status="ready"
        :model-value="filters.combination"
        @update:model-value="set('combination', $event as CombinationId[])"
      />
      <MultiSelect
        id="risk-provider"
        label="Provider"
        :options="providerOptions"
        status="ready"
        :model-value="filters.provider"
        @update:model-value="set('provider', $event as RiskFilters['provider'])"
      />
      <MultiSelect id="risk-type" label="Type" :options="typeOptions" :status="facetStatus" :model-value="filters.type" @update:model-value="set('type', $event)" />
    </FilterBar>

    <section class="card panel" aria-labelledby="risk-list-h">
      <div class="panel-h">
        <div class="titles">
          <h2 id="risk-list-h" class="h2">Resources at risk</h2>
          <span class="cap">Worst first. Read-only: each fact opens where to fix it. At risk since: the first scan Risk saw it in, with no backfill before Risk existed.</span>
        </div>
      </div>

      <div v-if="error" class="panel-body">
        <AlertBanner kind="fail">
          Risk didn't load: {{ error }}
          <template #action><button type="button" class="btn btn-secondary btn-sm" @click="retry">Retry</button></template>
        </AlertBanner>
      </div>
      <div v-else-if="!loaded" aria-busy="true" class="panel-body loading"><div v-for="n in 5" :key="n" class="skeleton sk-48"></div></div>
      <div v-else-if="noConnections" class="panel-body">
        <EmptyState icon="plug" title="No accounts yet." text="Add an account, scan it, and Risk is worked out from what the scans find.">
          <RouterLink class="btn btn-ghost" :to="{ name: 'connections' }">Go to Connections</RouterLink>
        </EmptyState>
      </div>
      <div v-else-if="!computedScope" class="panel-body">
        <EmptyState icon="clock" title="Risk not computed yet for this account." text="It is worked out after the account's next scan." />
      </div>
      <div v-else-if="rows.length === 0 && filtered" class="panel-body">
        <EmptyState icon="info" title="No resource matches these filters.">
          <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
        </EmptyState>
      </div>
      <div v-else-if="rows.length === 0" class="panel-body">
        <EmptyState icon="check" title="Nothing at risk." text="No resource in this account matches a combination." />
      </div>
      <div v-else ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="risk-list-h" :aria-busy="loading">
        <table class="table stackable stack-narrow dense risk-table">
          <thead>
            <tr><th scope="col">Resource</th><th scope="col">Risk</th><th scope="col">Facts</th><th scope="col" class="right">At risk since</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in rows" :key="r.resource_id">
              <td data-label="Resource" class="name">
                <span class="name-block">
                  <RouterLink class="btn btn-ghost btn-sm open" :to="openQuery(r.resource_id)">{{ label(r) }}</RouterLink>
                  <span class="sub conn"><ProviderTag :provider="r.provider" /><span class="mono">{{ r.resource_type }}</span> · {{ connectionName(r.connection_id) }}</span>
                </span>
              </td>
              <td data-label="Risk">
                <ul class="chips">
                  <li v-for="c in r.combinations" :key="c" class="combo-chip"><SeverityTag :severity="tierOf(c)" compact /><span>{{ title(c) }}</span></li>
                </ul>
              </td>
              <td data-label="Facts" class="facts">
                <!-- One container: a stacked row lays each child of a cell on its own line. -->
                <span class="facts-line">
                  <template v-for="(f, i) in riskFacts(r)" :key="f.key">
                    <span v-if="i" aria-hidden="true" class="soft"> · </span>
                    <RouterLink v-if="f.to" class="fact-link" :to="f.to">{{ f.text }}</RouterLink>
                    <RouterLink v-else-if="f.panel" class="fact-link" :to="{ ...openQuery(r.resource_id), hash: f.panel === 'door' ? '#from-internet' : '' }">{{ f.text }}</RouterLink>
                    <span v-else>{{ f.text }}</span>
                  </template>
                </span>
              </td>
              <td data-label="At risk since" class="right since">
                <span class="since-block">
                  <span class="mono">{{ r.first_seen }}</span>
                  <span v-if="r.door_held_since" class="sub held">
                    <AppIcon name="warning" :size="12" />Reach not re-checked since <span class="mono">{{ r.door_held_since }}</span>
                  </span>
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="rows.length" class="panel-foot">
        <AppPagination :total="total" :page="page" :limit="PAGE" @change="goTo" />
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

<style scoped src="@/views/investigate/summary/summary.css"></style>
<style scoped>
.three {
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
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

.combos {
  margin: 0;
  padding: 0;
  list-style: none;
}

.combo {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--s-12);
  padding: var(--s-10) var(--s-18);
  border-bottom: 1px solid var(--border);
}

.combo:last-child {
  border-bottom: 0;
}

.combo-name {
  display: flex;
  align-items: flex-start;
  gap: var(--s-10);
  min-width: 0;
}

.combo-title {
  font-size: 13px;
  color: var(--text);
}

.combo-count {
  flex: none;
  font-size: 13px;
}

.sub {
  display: block;
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
  overflow-wrap: anywhere;
}

.soft {
  color: var(--text-3);
}

.conn {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-6);
}

.open {
  max-width: 420px;
  padding: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  justify-content: flex-start;
}

.chips {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  margin: 0;
  padding: 0;
  list-style: none;
}

.combo-chip {
  display: flex;
  align-items: baseline;
  gap: var(--s-6);
  font-size: 12px;
  overflow-wrap: anywhere;
}

.facts {
  font-size: 12px;
  line-height: 1.6;
}

.facts-line {
  display: block;
}

.fact-link {
  color: inherit;
  text-decoration: underline;
  text-underline-offset: 2px;
}

.since {
  white-space: nowrap;
}

.name-block,
.since-block {
  display: block;
}

.held {
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
  color: var(--text-2);
  white-space: normal;
}
</style>
