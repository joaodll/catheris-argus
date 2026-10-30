<script setup lang="ts">
/**
 * Posture -> Compliance (docs/ui/screens.md, E9): every Prowler framework's score, its trend
 * and its requirements, for all connections or one. Read-only. The URL holds the search, the
 * providers, the connection, the order and the page.
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import Sparkline from '@/components/charts/Sparkline.vue'
import EmptyState from '@/components/EmptyState.vue'
import FilterBar from '@/components/FilterBar.vue'
import MultiSelect, { type MultiOption } from '@/components/MultiSelect.vue'
import PageHeader from '@/components/PageHeader.vue'
import ProviderTag from '@/components/ProviderTag.vue'
import SortHeader from '@/components/SortHeader.vue'
import { useResource } from '@/composables/useResource'
import { decimal, monthName, scoreColor } from '@/format'
import { PROVIDERS, type Provider } from '@/providers'
import { frameworkName, listToQuery, parseList, scoreChange, scoreText, type ListQuery } from './compliance'

const PAGE = 20
// GCP and OCI are offered, marked, so the filter reads the same once they are covered (as Findings).
const providerOptions: MultiOption[] = PROVIDERS.map((p) => ({ value: p.id, label: p.name, note: p.covered ? undefined : 'not covered' }))
const route = useRoute()
const router = useRouter()
// Frozen while the router leaves this page: the list must not reload for the next page's URL.
const state = ref<ListQuery>(parseList(route.query))
watch(
  () => route.fullPath,
  () => {
    if (route.name === 'compliance') state.value = parseList(route.query)
  },
)

function navigate(change: Partial<ListQuery>, replace = false): void {
  const query = listToQuery({ ...state.value, page: 1, ...change })
  void (replace ? router.replace({ query }) : router.push({ query }))
}

const search = ref(state.value.q)
let typing: number | undefined
watch(search, (value) => {
  window.clearTimeout(typing)
  typing = window.setTimeout(() => {
    if (value.trim() !== state.value.q) navigate({ q: value.trim() }, true)
  }, 300)
})
watch(
  () => state.value.q,
  (q) => {
    if (q !== search.value.trim()) search.value = q
  },
)
onBeforeUnmount(() => window.clearTimeout(typing))

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const list = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/compliance', {
        params: {
          query: {
            connection_id: state.value.connection,
            q: state.value.q || null,
            provider: state.value.provider,
            order: state.value.order,
            limit: PAGE,
            offset: (state.value.page - 1) * PAGE,
          },
        },
      }),
    ),
  { watch: [() => JSON.stringify(listToQuery(state.value))] },
)

const items = computed<Schemas['FrameworkListItem'][]>(() => list.data.value?.items ?? [])
const filtered = computed(() => Boolean(state.value.q || state.value.provider.length || state.value.connection))
const connectionName = computed(() => connections.data.value?.find((c) => c.id === state.value.connection)?.name ?? 'this connection')
const loaded = computed(() => list.data.value != null)
const noData = computed(() => loaded.value && list.data.value?.data_through == null && !filtered.value)

function clearFilters(): void {
  window.clearTimeout(typing)
  search.value = ''
  navigate({ q: '', provider: [], connection: 0 })
}

function toggleScore(): void {
  navigate({ order: state.value.order === 'score_asc' ? 'score_desc' : 'score_asc' })
}

function toggleName(): void {
  navigate({ order: state.value.order === 'name_asc' ? 'name_desc' : 'name_asc' })
}

function trendText(f: Schemas['FrameworkListItem']): string {
  const first = f.trend[0]
  const last = f.trend[f.trend.length - 1]
  if (!first || !last || f.trend.length < 2) return 'Not enough history for a trend.'
  return `From ${decimal(first.score)} % to ${decimal(last.score)} % over ${f.trend.length} weeks.`
}

function link(f: Schemas['FrameworkListItem']): { name: string; params: { framework: string }; query: Record<string, string> } {
  return {
    name: 'framework',
    params: { framework: f.framework },
    query: state.value.connection ? { connection: String(state.value.connection) } : {},
  }
}

const table = ref<HTMLElement | null>(null)
function goTo(page: number): void {
  void router.push({ query: listToQuery({ ...state.value, page }) }).then(() => table.value?.focus())
}
</script>

<template>
  <PageHeader title="Compliance">
    <template v-if="list.data.value?.data_through">Data through <span class="mono strong">{{ list.data.value.data_through }}</span></template>
    <template v-else-if="loaded">No Prowler scan yet</template>
    <template v-if="!state.connection && list.data.value?.data_through"> · All connections: each account's latest scan, up to 31 days old</template>
  </PageHeader>

  <FilterBar label="Filter frameworks" :active="filtered" @clear="clearFilters">
    <div class="field search">
      <label class="lbl" for="c-q">Search</label>
      <span class="search-wrap">
        <AppIcon name="search" :size="16" class="search-icon" />
        <input id="c-q" v-model="search" class="input" type="search" placeholder="Search frameworks" maxlength="200" autocomplete="off">
      </span>
    </div>
    <MultiSelect
      id="c-provider"
      label="Provider"
      :options="providerOptions"
      :model-value="state.provider"
      @update:model-value="navigate({ provider: $event as Provider[] })"
    />
    <div class="field">
      <label class="lbl" for="c-conn">Connection</label>
      <select id="c-conn" class="select" :value="state.connection" @change="navigate({ connection: Number(($event.target as HTMLSelectElement).value) || 0 })">
        <option :value="0">All connections</option>
        <option v-for="c in connections.data.value ?? []" :key="c.id" :value="c.id">{{ c.name }}</option>
      </select>
    </div>
  </FilterBar>

  <!-- The Platform's list panel: a header bar, the table edge to edge, a footer bar. -->
  <section class="card panel" aria-labelledby="frameworks-h">
    <div class="panel-h">
      <div class="titles">
        <h2 id="frameworks-h" class="h2">Frameworks</h2>
        <span class="cap">Score: requirements passed ÷ assessed, manual requirements excluded. Prowler checks every framework in one run.</span>
      </div>
    </div>

    <div v-if="list.error.value" class="panel-body">
      <AlertBanner kind="fail">
        Compliance didn't load: {{ list.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="list.reload()">Retry</button></template>
      </AlertBanner>
    </div>
    <div v-else-if="!loaded" aria-busy="true" class="panel-body loading"><div v-for="n in 6" :key="n" class="skeleton sk-48"></div></div>
    <div v-else-if="noData" class="panel-body">
      <EmptyState icon="checklist" title="No compliance results yet." text="Scores appear after a Prowler scan is ingested.">
        <RouterLink class="btn btn-ghost" :to="{ name: 'schedules' }">Go to Schedules</RouterLink>
      </EmptyState>
    </div>
    <div v-else-if="items.length === 0 && (state.q || state.provider.length)" class="panel-body">
      <EmptyState icon="info" title="No frameworks match these filters.">
        <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
      </EmptyState>
    </div>
    <div v-else-if="items.length === 0" class="panel-body">
      <EmptyState
        icon="checklist"
        :title="`No compliance results for ${connectionName}.`"
        text="Run Prowler for this connection, or choose All connections."
      />
    </div>
    <div v-else ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="frameworks-h" :aria-busy="list.loading.value">
      <table class="table stackable stack-narrow dense frameworks">
        <thead>
          <tr>
            <SortHeader
              label="Framework"
              :direction="state.order === 'name_asc' ? 'asc' : state.order === 'name_desc' ? 'desc' : null"
              desc-text="Z to A"
              asc-text="A to Z"
              @toggle="toggleName"
            />
            <SortHeader
              label="Score"
              :direction="state.order === 'score_asc' ? 'asc' : state.order === 'score_desc' ? 'desc' : null"
              desc-text="highest first"
              asc-text="lowest first"
              @toggle="toggleScore"
            />
            <th scope="col" class="hide-narrow">Trend</th>
            <th scope="col" class="right">Change</th>
            <th scope="col">Requirements</th>
            <th scope="col" class="right hide-narrow">Last assessed</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in items" :key="f.framework">
            <td data-label="Framework" class="fw">
              <RouterLink class="fw-link" :class="{ mono: !f.name }" :to="link(f)">{{ frameworkName(f) }}</RouterLink>
              <span class="fw-meta"><ProviderTag :provider="f.provider" /><span v-if="f.name" class="mono key">{{ f.framework }}</span></span>
            </td>
            <td data-label="Score">
              <span v-if="f.score != null" class="score">
                <span class="score-line"><span class="dot mark-dot" :style="{ '--series': scoreColor(f.score) }"></span><b class="mono">{{ scoreText(f.score) }}</b></span>
                <span class="meter mark-track" aria-hidden="true"><span class="fill mark-bar" :style="{ width: `${Math.min(100, Math.max(0, f.score))}%`, '--series': scoreColor(f.score) }"></span></span>
              </span>
              <span v-else class="cap">Not assessed</span>
            </td>
            <td data-label="Trend" class="hide-narrow">
              <span v-if="f.trend.length >= 2" class="trend"><Sparkline :values="f.trend.map((p) => p.score)" /><span class="sr-only">{{ trendText(f) }}</span></span>
              <span v-else class="soft">—</span>
            </td>
            <td data-label="Change" class="right">
              <span
                class="mono change"
                :style="{ color: scoreChange(f.change).color }"
                :title="f.change_since ? `Since ${monthName(f.change_since)}` : undefined"
                :aria-label="f.change_since ? `${scoreChange(f.change).label} since ${monthName(f.change_since)}` : scoreChange(f.change).label"
              >{{ scoreChange(f.change).text }}</span>
            </td>
            <td data-label="Requirements">
              <span v-if="f.requirements" class="counts mono">
                <span class="ok" :aria-label="`${f.requirements.pass} passed`"><AppIcon name="check" :size="14" />{{ f.requirements.pass }}</span>
                <span class="fail" :aria-label="`${f.requirements.fail} failed`"><AppIcon name="cross" :size="14" />{{ f.requirements.fail }}</span>
                <span class="manual" :aria-label="`${f.requirements.manual} manual`" title="Manual requirements are not scored"><AppIcon name="half" :size="14" />{{ f.requirements.manual }}</span>
              </span>
              <span v-else class="soft">—</span>
            </td>
            <td data-label="Last assessed" class="right mono hide-narrow">{{ f.latest_day ?? '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="items.length" class="panel-foot">
      <AppPagination :total="list.data.value?.total ?? 0" :page="state.page" :limit="PAGE" noun="framework" @change="goTo" />
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

.frameworks tbody tr:hover {
  background: var(--surface-raised);
}

/* The framework column takes the width the others leave; its name may wrap. */
.fw {
  width: 100%;
  white-space: normal;
}

.fw-link {
  display: block;
}

.fw-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-4) var(--s-10);
  margin-top: 3px;
}

.frameworks td {
  white-space: nowrap;
}

.fw-link {
  color: var(--link);
  font-size: 13px;
  font-weight: 600;
  text-decoration: none;
}

.fw-link:hover {
  text-decoration: underline;
}

.key {
  font-size: 11px;
  color: var(--text-3);
  overflow-wrap: anywhere;
}

.score {
  display: inline-flex;
  flex-direction: column;
  gap: var(--s-4);
}

.score-line {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.score-line b {
  font-weight: 600;
}

.dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
}

.meter {
  display: block;
  width: 96px;
  height: 4px;
  border-radius: 999px;
  overflow: hidden;
}

.fill {
  display: block;
  height: 100%;
  border-radius: 999px;
}

.trend {
  display: inline-block;
}

.change {
  font-size: 12px;
  white-space: nowrap;
}

.counts {
  display: inline-flex;
  gap: var(--s-12);
  font-size: 12px;
}

.counts > span {
  display: inline-flex;
  align-items: center;
  gap: 3px;
}

.ok {
  color: var(--status-ok);
}

.fail {
  color: var(--status-fail);
}

.manual,
.soft {
  color: var(--text-3);
}

@media (max-width: 899px) {
  .hide-narrow {
    display: none;
  }
}
</style>
