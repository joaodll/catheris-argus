<script setup lang="ts">
/**
 * Investigate → Resources → Summary (owner's decisions 2026-11-06; spec in the palace,
 * frontend/1830b32f on round 1's frontend/0064ccbd). The cloud inventory: how many assets, where
 * (categories, accounts, regions, services), what changed (added and removed per week), and how many
 * assets carry a critical or high misconfiguration, a CVE with a public exploit, or a confirmed
 * way in from the internet. Every number comes from stored counts (GET /resources/summary) and
 * links to the List tab with the filters that reproduce it, Assets only. The summary follows
 * its own account picker only.
 */
import { computed } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import SeverityBars, { type SeverityBarItem } from '@/components/charts/SeverityBars.vue'
import WeeklyFlow from '@/components/charts/WeeklyFlow.vue'
import { useResource } from '@/composables/useResource'
import { int } from '@/format'
import { bySize, groupTypes } from '@/views/overview/assetTypes'
import CategoryRows from '@/views/overview/CategoryRows.vue'
import { regionLabel, typesByService } from '../labels'
import { type ResourceFilters, resourcesLink } from '../resourceFilters'
import SummaryHeader from './SummaryHeader.vue'

const props = defineProps<{ connectionId: number; connections: Schemas['ConnectionOut'][] | null }>()
const emit = defineEmits<{ selectConnection: [id: number] }>()

const TOP = 10
const RECENT_DAYS = 30
const STEAMPIPE = 'var(--tool-steampipe)' // the inventory is Steampipe's: its fixed tool colour
const scope = computed(() => (props.connectionId ? [props.connectionId] : []))

const summary = useResource(() => unwrap(api.GET('/api/v1/resources/summary', { params: { query: { connection_id: props.connectionId } } })), {
  watch: [() => props.connectionId],
})

/** The List tab with what every summary number counts (the account's assets), plus `extra`. */
function list(extra: Partial<ResourceFilters> = {}): RouteLocationRaw {
  return resourcesLink({ assets: true, connection: scope.value, ...extra })
}

const data = computed(() => summary.data.value)
const assets = computed(() => data.value?.assets ?? null)

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10)
}
// The 30-day tile's links: the window the API counts (today and the 29 days before it).
const window30 = computed(() => {
  const today = new Date()
  const from = new Date(today)
  from.setUTCDate(today.getUTCDate() - (RECENT_DAYS - 1))
  return { from: isoDay(from), to: isoDay(today) }
})

const recent = computed(() => data.value?.last_30_days ?? null)

type RiskKey = 'critical_high' | 'exploitable' | 'reachable'
const RISKS: { key: RiskKey; label: string; filters: Partial<ResourceFilters>; noScan: string }[] = [
  { key: 'critical_high', label: 'Critical or high misconfiguration', filters: { misconfigurations: 'high' }, noScan: 'No Prowler or CloudFox scan yet' },
  { key: 'exploitable', label: 'Public exploit', filters: { vulnerabilities: 'exploitable' }, noScan: 'No vulnerabilities scan yet' },
  { key: 'reachable', label: 'Internet reachable', filters: { internet: true }, noScan: 'No Prowler or CloudFox scan yet' },
]
const risks = computed(() =>
  RISKS.map((r) => {
    const value = data.value?.at_risk[r.key] ?? null
    return { ...r, value, stale: value != null && value.as_of !== data.value?.data_through }
  }),
)

// By category: the Overview's rows (CategoryRows), every provider together; each type opens
// the list filtered by it.
const typeCounts = computed(() => new Map((data.value?.by_type ?? []).map((t) => [t.type, t.count])))
const categories = computed(() => bySize(groupTypes(data.value?.by_type ?? [])))
const categoryTotal = computed(() => categories.value.reduce((n, g) => n + g.count, 0))
const categoryMax = computed(() => Math.max(1, ...categories.value.map((g) => g.count)))
const typeLink = (type: string) => list({ type: [type] })

const accounts = computed<SeverityBarItem[]>(() =>
  (data.value?.by_account?.items ?? []).map((a) => ({
    key: String(a.connection_id),
    label: a.name,
    total: a.total,
    to: list({ connection: [a.connection_id] }),
    dot: `var(--provider-${a.provider})`,
  })),
)
const regions = computed<SeverityBarItem[]>(() =>
  (data.value?.by_region?.items ?? []).map((r) => ({ key: r.value, label: regionLabel(r.value), total: r.total, to: list({ region: [r.value] }), mono: true })),
)
// By service: the types grouped as the Type filter groups them (typesByService), each linking
// with every type of the service.
const services = computed(() => {
  const counts = new Map((data.value?.by_type ?? []).map((t) => [t.type, t.count]))
  return typesByService([...counts.keys()])
    .map((g) => ({ ...g, total: g.types.reduce((n, t) => n + (counts.get(t) ?? 0), 0) }))
    .sort((a, b) => b.total - a.total || a.service.localeCompare(b.service))
})
const serviceBars = computed<SeverityBarItem[]>(() =>
  services.value.slice(0, TOP).map((s) => ({
    key: s.service,
    label: s.service,
    total: s.total,
    to: list({ type: s.types }),
    mono: true,
    sub: `${int(s.types.length)} type${s.types.length === 1 ? '' : 's'}`,
  })),
)
const moreServices = computed(() => Math.max(0, services.value.length - TOP))

const flowWeeks = computed(() => data.value?.weeks ?? [])
const noHistory = computed(() => flowWeeks.value.every((w) => w.added == null))

function total(items: SeverityBarItem[]): number {
  return items.reduce((n, i) => n + i.total, 0)
}
</script>

<template>
  <div class="summary">
    <SummaryHeader
      id-prefix="r-s"
      :connection-id="connectionId"
      :connections="connections"
      :data-through="data?.data_through"
      :loaded="Boolean(data)"
      :legend="false"
      @select-connection="emit('selectConnection', $event)"
    >
      Assets in each account's latest Steampipe inventory: parts, settings and links left out. Each number opens the list it counts.
    </SummaryHeader>

    <AlertBanner v-if="summary.error.value && !data" kind="fail">
      The summary didn't load: {{ summary.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="summary.reload()">Retry</button></template>
    </AlertBanner>

    <template v-else>
      <!-- Five tiles: CatherIs Platform's stat tiles (design-system.md, Card → Stat tile). -->
      <section aria-label="Key numbers" class="stat-grid five">
        <template v-if="data">
          <div class="stat-card tile">
            <div class="stat-label"><span>Assets</span></div>
            <b class="stat-value" :class="{ none: !assets }">{{ assets ? int(assets.total) : '—' }}</b>
            <span v-if="!assets" class="stat-sub">No Steampipe scan yet</span>
            <span v-else-if="connectionId" class="stat-sub">in {{ int(assets.regions) }} region{{ assets.regions === 1 ? '' : 's' }}</span>
            <span v-else class="stat-sub">
              in {{ int(assets.accounts) }} account{{ assets.accounts === 1 ? '' : 's' }} · {{ int(assets.regions) }} region{{ assets.regions === 1 ? '' : 's' }}
            </span>
            <RouterLink v-if="assets" class="drill-link" :to="list()" :aria-label="`Assets: ${int(assets.total)}. Show in list`">
              Show in list<AppIcon name="chevron" :size="14" :stroke="2" />
            </RouterLink>
          </div>

          <div class="stat-card tile">
            <div class="stat-label"><span>Last 30 days</span></div>
            <template v-if="recent">
              <b class="stat-value flow-value">
                <!-- A first scan in the window: its assets are its starting inventory, which the
                     list's first-seen filter would include, so "added" is not a link then. -->
                <span v-if="recent.baseline" class="mono">+{{ int(recent.added) }}</span>
                <RouterLink
                  v-else
                  class="inline-link mono"
                  :to="list({ firstSeenFrom: window30.from, firstSeenTo: window30.to, includeDeleted: true })"
                  :aria-label="`${int(recent.added)} added in the last 30 days. Show in list`"
                >+{{ int(recent.added) }}</RouterLink>
                <RouterLink
                  class="inline-link mono"
                  :to="list({ removedFrom: window30.from, removedTo: window30.to })"
                  :aria-label="`${int(recent.removed)} removed in the last 30 days. Show in list`"
                >−{{ int(recent.removed) }}</RouterLink>
              </b>
              <span v-if="recent.baseline" class="stat-sub">
                {{ int(recent.baseline) }} first scan{{ recent.baseline === 1 ? '' : 's' }}: their assets are the starting inventory, not counted as added
              </span>
              <span v-else class="stat-sub">added · removed</span>
              <a class="drill-link" href="#flow">Weekly trend<AppIcon name="chevron" :size="14" :stroke="2" /></a>
            </template>
            <template v-else>
              <b class="stat-value none">—</b>
              <span class="stat-sub">No Steampipe scan yet</span>
            </template>
          </div>

          <div v-for="r in risks" :key="r.key" class="stat-card tile" :style="{ '--tone': r.value?.count ? 'var(--sev-high)' : undefined }">
            <div class="stat-label"><span>{{ r.label }}</span></div>
            <b class="stat-value" :class="{ none: !r.value }">{{ r.value ? int(r.value.count) : '—' }}</b>
            <span v-if="!r.value" class="stat-sub">{{ r.noScan }}</span>
            <span v-else class="stat-sub">
              <template v-if="r.value.count && assets">of {{ int(assets.total) }} assets</template>
              <template v-else-if="!r.value.count">None</template>
              <template v-if="r.stale"> · as of <span class="mono">{{ r.value.as_of }}</span></template>
            </span>
            <RouterLink v-if="r.value" class="drill-link" :to="list(r.filters)" :aria-label="`${r.label}: ${int(r.value.count)} assets. Show in list`">
              Show in list<AppIcon name="chevron" :size="14" :stroke="2" />
            </RouterLink>
          </div>
        </template>
        <template v-else>
          <div v-for="n in 5" :key="n" class="stat-card skeleton"></div>
        </template>
      </section>

      <div v-if="!data" class="grid" aria-busy="true">
        <section v-for="n in 4" :key="n" class="card panel"><div class="panel-body loading"><div v-for="m in 5" :key="m" class="skeleton sk-44"></div></div></section>
      </div>

      <section v-else-if="!assets" class="card panel">
        <EmptyState icon="stack" title="Nothing to summarise yet." text="The summary fills in after the first Steampipe scan.">
          <RouterLink class="btn btn-ghost" :to="{ name: 'runs' }">Go to Runs</RouterLink>
        </EmptyState>
      </section>

      <template v-else>
        <section class="card panel" aria-labelledby="r-s-types">
          <div class="panel-h">
            <h2 id="r-s-types" class="h2">By category</h2>
            <span class="mono count">{{ int(data.by_type?.length ?? 0) }} types</span>
          </div>
          <div class="panel-body">
            <CategoryRows
              v-if="categories.length"
              id="r-s-cat"
              label="Assets by category"
              :groups="categories"
              :counts="typeCounts"
              :max="categoryMax"
              :total="categoryTotal"
              :type-link="typeLink"
              :more-link="list()"
              more-where="the list"
            />
            <p v-else class="none-open">No assets in the inventory.</p>
          </div>
        </section>

        <div class="grid">
          <section v-if="connectionId === 0" class="card panel" aria-labelledby="r-s-accounts">
            <div class="panel-h"><h2 id="r-s-accounts" class="h2">By account</h2><span class="mono count">{{ int(total(accounts)) }}</span></div>
            <div class="panel-body fit">
              <SeverityBars v-if="accounts.length" :items="accounts" :series="STEAMPIPE" noun="assets" />
              <p v-else class="none-open">No assets in the inventory.</p>
              <p v-if="data.by_account?.more" class="more cap">+ {{ int(data.by_account.more) }} more · <RouterLink class="drill-link" :to="list()">Show all in list</RouterLink></p>
            </div>
          </section>

          <section class="card panel" aria-labelledby="r-s-regions">
            <div class="panel-h"><h2 id="r-s-regions" class="h2">By region</h2></div>
            <div class="panel-body fit">
              <SeverityBars v-if="regions.length" :items="regions" :series="STEAMPIPE" noun="assets" />
              <p v-else class="none-open">No assets in the inventory.</p>
              <p v-if="data.by_region?.more" class="more cap">+ {{ int(data.by_region.more) }} more · <RouterLink class="drill-link" :to="list()">Show all in list</RouterLink></p>
            </div>
          </section>

          <section class="card panel" aria-labelledby="r-s-services">
            <div class="panel-h"><h2 id="r-s-services" class="h2">By service</h2></div>
            <div class="panel-body fit">
              <SeverityBars v-if="serviceBars.length" :items="serviceBars" :series="STEAMPIPE" noun="assets" />
              <p v-else class="none-open">No assets in the inventory.</p>
              <p v-if="moreServices" class="more cap">+ {{ int(moreServices) }} more · <RouterLink class="drill-link" :to="list()">Show all in list</RouterLink></p>
            </div>
          </section>
        </div>

        <section id="flow" class="card panel" aria-labelledby="r-s-flow" tabindex="-1">
          <div class="panel-h">
            <h2 id="r-s-flow" class="h2">Added and removed, last 12 weeks</h2>
          </div>
          <div class="panel-body">
            <p v-if="noHistory" class="none-open">No history yet: weeks fill in from the first scan after this release.</p>
            <WeeklyFlow v-else :weeks="flowWeeks" noun="assets" kind="assets" />
            <p class="cap">A first scan is an account's starting inventory: its assets are not counted as added.</p>
          </div>
        </section>
      </template>
    </template>
  </div>
</template>

<style scoped src="./summary.css"></style>

<style scoped>
.five {
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
}

.inline-link {
  color: inherit;
  text-decoration: underline;
  text-underline-offset: 2px;
}

.flow-value {
  display: inline-flex;
  gap: var(--s-10);
}
</style>
