<script setup lang="ts">
/**
 * Posture -> Compliance -> one framework (docs/ui/screens.md, E10): its score, the history,
 * each account month by month, and its requirements. Read-only. The URL holds the connection,
 * the range, the requirement filters and both pages.
 */
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import type { Range } from '@/components/charts/chart'
import EmptyState from '@/components/EmptyState.vue'
import ProviderTag from '@/components/ProviderTag.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { decimal, monthName, scoreColor } from '@/format'
import AccountMonths from './AccountMonths.vue'
import { frameworkName, frameworkToQuery, parseFramework, scoreChange, type FrameworkQuery, type Status } from './compliance'
import RequirementsCard from './RequirementsCard.vue'
import ScoreHistory from './ScoreHistory.vue'

// Every account on one card, to screenshot for a slide (2026-10-15); the API allows 200.
const ACCOUNTS_PAGE = 100
const REQUIREMENTS_PAGE = 50
const route = useRoute()
const router = useRouter()
// Frozen while the router leaves this page: its loads must not fire for the next page's URL.
const key = ref(String(route.params.framework ?? ''))
const state = ref<FrameworkQuery>(parseFramework(route.query))
watch(
  () => route.fullPath,
  () => {
    if (route.name !== 'framework') return
    key.value = String(route.params.framework ?? '')
    state.value = parseFramework(route.query)
  },
)

/** A change of connection, range or filter keeps scroll and focus (router.ts: same path). */
function navigate(change: Partial<FrameworkQuery>, replace = false): void {
  const query = frameworkToQuery({ ...state.value, ...change })
  void (replace ? router.replace({ query }) : router.push({ query }))
}

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const detail = useResource(
  async () => {
    try {
      return await unwrap(
        api.GET('/api/v1/compliance/{framework}', {
          params: { path: { framework: key.value }, query: { connection_id: state.value.connection, range: state.value.range } },
        }),
      )
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return 'not-found' as const
      throw err
    }
  },
  { watch: [key, () => state.value.connection, () => state.value.range] },
)
const accounts = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/compliance/{framework}/accounts', {
        params: { path: { framework: key.value }, query: { limit: ACCOUNTS_PAGE, offset: (state.value.apage - 1) * ACCOUNTS_PAGE } },
      }),
    ),
  { watch: [key, () => state.value.apage] },
)
const requirements = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/compliance/{framework}/requirements', {
        params: {
          path: { framework: key.value },
          query: {
            connection_id: state.value.connection,
            status: state.value.status,
            q: state.value.q || null,
            limit: REQUIREMENTS_PAGE,
            offset: (state.value.page - 1) * REQUIREMENTS_PAGE,
          },
        },
      }),
    ),
  { watch: [key, () => state.value.connection, () => state.value.status, () => state.value.q, () => state.value.page] },
)

const notFound = computed(() => detail.data.value === 'not-found')
const framework = computed(() => (detail.data.value && detail.data.value !== 'not-found' ? detail.data.value : null))
const title = computed(() => (notFound.value ? 'Framework not found' : framework.value ? frameworkName(framework.value) : key.value))
const connectionCount = computed(() => connections.data.value?.length ?? 0)
const scope = computed(() => {
  if (!state.value.connection) return 'All connections'
  return connections.data.value?.find((c) => c.id === state.value.connection)?.name ?? 'This connection'
})
const counts = computed(() => framework.value?.requirements ?? null)
// The breadcrumb's last part: the family when Prowler names one ("CIS"), else the key.
const crumb = computed(() => framework.value?.family ?? key.value)
const failTone = computed(() => ((counts.value?.fail ?? 0) > 0 ? 'var(--status-fail)' : 'var(--border-control)'))
const bar = computed(() => {
  const c = counts.value
  const total = c ? c.pass + c.fail + c.manual : 0
  if (!c || !total) return []
  return [
    { key: 'pass', width: (100 * c.pass) / total, color: 'var(--pass)' },
    { key: 'fail', width: (100 * c.fail) / total, color: 'var(--sev-critical)' },
    { key: 'manual', width: (100 * c.manual) / total, color: 'var(--muted)' },
  ]
})

// The tab names the framework once it loads, and again after each query change (the router
// resets the title on every navigation).
watch(
  [title, () => route.fullPath],
  ([name]) => {
    if (route.name === 'framework') document.title = `${name} · Compliance · Argus`
  },
  { immediate: true },
)

function selectRange(range: Range): void {
  navigate({ range }, true)
}
function selectConnection(id: number): void {
  navigate({ connection: id, page: 1 })
}
function setStatus(status: Status | null): void {
  navigate({ status, page: 1 })
}
function setSearch(q: string): void {
  navigate({ q, page: 1 }, true)
}
</script>

<template>
  <!-- A detail page (design-system.md, Page header): a breadcrumb, then a header card. -->
  <nav class="breadcrumb" aria-label="Breadcrumb">
    <RouterLink :to="{ name: 'compliance', query: state.connection ? { connection: String(state.connection) } : {} }">
      <AppIcon name="chevron" :size="13" :stroke="2.2" class="back-icon" />Compliance
    </RouterLink>
    <span class="sep" aria-hidden="true">/</span>
    <span aria-current="page">{{ notFound ? 'Not found' : crumb }}</span>
  </nav>
  <header class="card detail-head">
    <div class="detail-title">
      <h1 tabindex="-1" data-page-title>{{ title }}</h1>
      <span v-if="framework" class="detail-badges"><ProviderTag :provider="framework.provider" /><ToolChip tool="prowler" /></span>
    </div>
    <dl v-if="framework" class="detail-facts">
      <div>
        <dt><span aria-hidden="true">📅 </span>Data through</dt>
        <dd><span v-if="framework.data_through" class="mono">{{ framework.data_through }}</span><template v-else>No Prowler scan yet</template></dd>
      </div>
      <div>
        <dt><span aria-hidden="true">🖥 </span>Scope</dt>
        <dd>{{ state.connection ? scope : "All connections · each account's latest scan, up to 31 days old" }}</dd>
      </div>
      <div>
        <dt><span aria-hidden="true">🏷 </span>Key</dt>
        <dd class="mono">{{ framework.framework }}</dd>
      </div>
    </dl>
  </header>

  <section v-if="notFound" class="card">
    <EmptyState icon="info" title="Argus has no results for this framework." :text="`Nothing is recorded for ${key}.`">
      <RouterLink class="btn btn-secondary" :to="{ name: 'compliance' }">Back to Compliance</RouterLink>
    </EmptyState>
  </section>

  <template v-else>
    <section class="card scope-bar" aria-label="Scope">
      <div class="field">
        <label class="lbl" for="fw-conn">Connection</label>
        <select id="fw-conn" class="select" :value="state.connection" @change="selectConnection(Number(($event.target as HTMLSelectElement).value) || 0)">
          <option :value="0">All connections</option>
          <option v-for="c in connections.data.value ?? []" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </div>
    </section>

    <AlertBanner v-if="detail.error.value" kind="fail">
      The framework didn't load: {{ detail.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="detail.reload()">Retry</button></template>
    </AlertBanner>

    <!-- The Platform's stat tiles (design-system.md, Card → Stat tile). -->
    <section aria-label="Key metrics" class="stat-grid tiles">
      <template v-if="framework">
        <div class="stat-card tile" :style="{ '--tone': framework.score != null ? scoreColor(framework.score) : 'var(--border-control)' }">
          <div class="stat-label"><span>Score</span></div>
          <template v-if="framework.score != null">
            <b class="stat-value" :style="{ color: scoreColor(framework.score) }">{{ decimal(framework.score) }}<span class="unit">%</span></b>
            <div class="meter mark-track" role="img" :aria-label="`Score ${decimal(framework.score)} of 100`">
              <div class="fill mark-bar" :style="{ width: `${Math.min(100, Math.max(0, framework.score))}%`, '--series': scoreColor(framework.score) }"></div>
            </div>
            <span class="stat-sub">Requirements passed ÷ assessed, manual excluded</span>
          </template>
          <template v-else>
            <b class="stat-value none">Not assessed</b>
            <span class="stat-sub">No score for {{ scope }} yet</span>
          </template>
        </div>
        <div class="stat-card tile" :style="{ '--tone': failTone }">
          <div class="stat-label"><span>Failing requirements</span></div>
          <template v-if="counts">
            <b class="stat-value" :style="{ color: counts.fail > 0 ? 'var(--status-fail)' : undefined }">{{ counts.fail }}</b>
            <div v-if="bar.length" class="stack-bar" aria-hidden="true">
              <span v-for="b in bar" :key="b.key" :style="{ width: `${b.width}%`, background: b.color }"></span>
            </div>
            <span class="stat-sub">
              <span class="ok">✓ {{ counts.pass }} pass</span> · ◐ {{ counts.manual }} manual<template v-if="!state.connection"> · across {{ connectionCount }} account{{ connectionCount === 1 ? '' : 's' }}</template>
            </span>
          </template>
          <template v-else>
            <b class="stat-value none">Not assessed</b>
            <span class="stat-sub">No requirements recorded for {{ scope }}</span>
          </template>
        </div>
        <div class="stat-card tile">
          <div class="stat-label"><span>Change</span></div>
          <b class="stat-value" :style="{ color: scoreChange(framework.change).color }" :aria-label="scoreChange(framework.change).label">{{ scoreChange(framework.change).text }}</b>
          <span class="stat-sub">{{ framework.change_since ? `Points since ${monthName(framework.change_since)}` : 'Needs two months of history' }}</span>
        </div>
      </template>
      <template v-else-if="!detail.error.value">
        <div v-for="n in 3" :key="n" class="stat-card skeleton"></div>
      </template>
    </section>

    <ScoreHistory :detail="framework" :range="state.range" :scope="scope" @select-range="selectRange" />

    <AccountMonths
      :framework="framework ? frameworkName(framework) : null"
      :provider="framework?.provider ?? null"
      :accounts="accounts.data.value"
      :error="accounts.error.value"
      :selected="state.connection"
      :page="state.apage"
      :limit="ACCOUNTS_PAGE"
      @select="selectConnection"
      @page="navigate({ apage: $event })"
      @retry="accounts.reload()"
    />

    <RequirementsCard
      :requirements="requirements.data.value"
      :error="requirements.error.value"
      :all-connections="!state.connection"
      :scope="scope"
      :status="state.status"
      :q="state.q"
      :page="state.page"
      :limit="REQUIREMENTS_PAGE"
      @status="setStatus"
      @search="setSearch"
      @page="navigate({ page: $event })"
      @retry="requirements.reload()"
    />
  </template>
</template>

<style scoped>
.scope-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--s-12) var(--s-16);
  padding: var(--s-16);
}

.scope-bar .select {
  min-width: 220px;
}

/* Three tiles in a row; one under 900 px. */
.tiles {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

@media (max-width: 899px) {
  .tiles {
    grid-template-columns: minmax(0, 1fr);
  }
}

.tile {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.stat-value.none {
  font-size: 15px;
  color: var(--text-3);
}

.unit {
  margin-left: 2px;
  font-size: 18px;
}

.meter {
  height: 6px;
  margin: var(--s-4) 0;
  border-radius: 3px;
}

.fill {
  height: 100%;
  border-radius: 3px;
}

.stack-bar {
  display: flex;
  height: 8px;
  margin: var(--s-4) 0;
  overflow: hidden;
  border-radius: 4px;
  background: var(--track);
}

.ok {
  color: var(--status-ok);
}
</style>
