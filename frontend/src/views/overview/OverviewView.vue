<script setup lang="ts">
/**
 * The executive Overview (board D1, docs/design.md "Overview screen"). Every block reads the
 * Overview read model, which comes from metric_daily only, as of the latest scan: the page shows
 * the current state, and history lives in its trend blocks. The selection (connection, severity
 * range, the strip's framework) lives in the URL, so a view can be shared and survives a reload;
 * the strip's framework is also remembered in this browser.
 */
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppShell from '@/components/AppShell.vue'
import { parseRange, type Range } from '@/components/charts/chart'
import EmptyState from '@/components/EmptyState.vue'
import PageHeader from '@/components/PageHeader.vue'
import { useResource } from '@/composables/useResource'
import AttackPathsCard from './AttackPathsCard.vue'
import ContextBar from './ContextBar.vue'
import InventoryCard from './InventoryCard.vue'
import KpiCards from './KpiCards.vue'
import ProwlerCard from './ProwlerCard.vue'
import { loadStrip, parseStrip, saveStrip } from './stripChoice'
import ThreatScoreStrip from './ThreatScoreStrip.vue'

const route = useRoute()
const router = useRouter()

const connectionId = computed(() => Number(route.query.connection ?? 0) || 0)
const range = computed<Range>(() => parseRange(route.query.range))

function select(change: Record<string, string | number | undefined>): void {
  void router.replace({ query: { ...route.query, ...change } })
}

// The strip's framework: the URL wins; without one, the last choice made in this browser.
const strip = computed(() => parseStrip(route.query.strip))
if (!route.query.strip) {
  const saved = loadStrip()
  if (saved) select({ strip: saved })
}
function chooseStrip(key: string): void {
  saveStrip(key)
  select({ strip: key || undefined })
}

const context = useResource(
  () => unwrap(api.GET('/api/v1/context', { params: { query: { connection_id: connectionId.value } } })),
  { watch: [connectionId] },
)
const overview = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/overview', {
        params: { query: { connection_id: connectionId.value, range: range.value } },
      }),
    ),
  { watch: [connectionId, range] },
)

const connections = computed(() => context.data.value?.connections ?? [])
const scope = computed(() => {
  const chosen = connections.value.find((c) => c.id === connectionId.value)
  if (chosen) return `${chosen.name} · AWS account ${chosen.account_id}`
  const n = connections.value.length
  return `${n} connection${n === 1 ? '' : 's'} · AWS · each account's latest scan, up to 31 days old`
})
const noData = computed(() => overview.data.value !== null && overview.data.value.data_through === null)
</script>

<template>
  <AppShell>
    <PageHeader title="Overview">{{ scope }}</PageHeader>

    <ContextBar
      :context="context.data.value"
      :overview="overview.data.value"
      :connection-id="connectionId"
      @select-connection="(id) => select({ connection: id })"
    />

    <AlertBanner v-if="overview.error.value && overview.data.value" kind="fail">
      Argus can't refresh this page: {{ overview.error.value }} The last loaded data is shown, dimmed.
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="overview.reload">Retry</button></template>
    </AlertBanner>

    <section v-if="overview.error.value && !overview.data.value" class="card">
      <AlertBanner kind="fail">
        The Overview didn't load: {{ overview.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="overview.reload">Retry</button></template>
      </AlertBanner>
    </section>

    <section v-else-if="noData" class="card">
      <EmptyState
        title="No scan yet for this selection."
        text="Add a connection in Administration, or run the collectors from Operate → Schedules. History appears here after the first complete scan."
      >
        <RouterLink class="btn btn-primary" :to="{ name: 'connections' }">Open Administration</RouterLink>
      </EmptyState>
    </section>

    <div v-else class="blocks" :class="{ dim: overview.error.value }" :aria-busy="overview.loading.value">
      <KpiCards :data="overview.data.value" :connection-count="connections.length" :connection-id="connectionId" />
      <ThreatScoreStrip :data="overview.data.value" :connection-id="connectionId" :framework="strip" @choose="chooseStrip" />
      <ProwlerCard :data="overview.data.value" :range="range" :connection-id="connectionId" @select-range="(r) => select({ range: r })" />
      <div class="split">
        <AttackPathsCard :data="overview.data.value" :connection-id="connectionId" />
        <InventoryCard :data="overview.data.value" :connection-id="connectionId" />
      </div>
    </div>
  </AppShell>
</template>

<style scoped>
.blocks {
  display: flex;
  flex-direction: column;
  gap: var(--s-14);
}

.split {
  display: grid;
  grid-template-columns: minmax(0, 5fr) minmax(0, 7fr);
  gap: var(--s-14);
  align-items: start;
}

@media (max-width: 1150px) {
  .split {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
