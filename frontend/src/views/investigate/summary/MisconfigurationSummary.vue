<script setup lang="ts">
/**
 * Investigate → Misconfigurations → Summary (owner's decision 2026-11-05; spec in the palace,
 * frontend/0064ccbd). Detail the Overview doesn't have: where open misconfigurations are (accounts,
 * services, regions), what kind (categories, checks, reach), how old, and whether more open than
 * close. Every number comes from stored counts (GET /findings/summary) and links to the List tab
 * with the filters that reproduce it: open, failing, not muted, Prowler and CloudFox. Top checks
 * are the list by check with those filters. The summary follows its own account picker only.
 */
import { computed } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import SeverityBars, { type SeverityBarItem } from '@/components/charts/SeverityBars.vue'
import SeverityColumns, { type SeverityColumn } from '@/components/charts/SeverityColumns.vue'
import WeeklyFlow from '@/components/charts/WeeklyFlow.vue'
import { useResource } from '@/composables/useResource'
import { int } from '@/format'
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_TEXT, type Severity } from '@/views/overview/severity'
import { type FindingFilters, type Tool, categoryLabel, emptyFilters, filtersToQuery } from '../findingFilters'
import { regionLabel } from '../labels'
import type { FindingReach } from '../reachReason'

const props = defineProps<{ connectionId: number; connections: Schemas['ConnectionOut'][] | null }>()
const emit = defineEmits<{ selectConnection: [id: number] }>()

const TOP = 10
const scope = computed(() => (props.connectionId ? [props.connectionId] : []))

const summary = useResource(() => unwrap(api.GET('/api/v1/findings/summary', { params: { query: { connection_id: props.connectionId } } })), {
  watch: [() => props.connectionId],
})
const checks = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/findings/groups', {
        params: { query: { limit: TOP, offset: 0, order: 'severity', status: ['FAIL'], muted: 'hide', connection_id: scope.value } },
      }),
    ),
  { watch: [() => props.connectionId] },
)

/** The List tab with what every summary number counts, plus `extra`. */
function list(extra: Partial<FindingFilters> = {}, view?: 'checks'): RouteLocationRaw {
  const filters: FindingFilters = { ...emptyFilters(), result: ['FAIL'], muted: 'hide', connection: scope.value, ...extra }
  return { name: 'misconfigurations', query: { ...filtersToQuery(filters), view, tab: 'list' } }
}

const data = computed(() => summary.data.value)
const open = computed(() => data.value?.open ?? null)
const scanned = computed(() => open.value != null)
const noScan = computed(() =>
  props.connectionId ? 'No Prowler or CloudFox scan of this account yet' : 'No Prowler or CloudFox scan yet',
)

function counts(s: Schemas['SeverityCounts']): Record<Severity, number> {
  return { critical: s.critical, high: s.high, medium: s.medium, low: s.low, informational: s.informational }
}

const tiles = computed(() => {
  const o = open.value
  const recent = data.value?.last_30_days ?? null
  const reach = data.value?.reach ?? []
  const reachable = reach.find((r) => r.value === 'confirmed')?.total ?? 0
  const restricted = reach.find((r) => r.value === 'restricted')?.total ?? 0
  const critical = o?.severities.critical ?? 0
  const high = o?.severities.high ?? 0
  const total = o?.total ?? 0
  return {
    open: o ? { value: int(total), sub: total ? `Prowler ${int(o.tools.prowler)} · CloudFox ${int(o.tools.cloudfox)}` : 'Nothing open' } : null,
    severe: o
      ? {
          value: int(critical + high),
          critical,
          high,
          widths: total ? [(critical / total) * 100, (high / total) * 100] : [0, 0],
        }
      : null,
    recent: recent
      ? { opened: recent.opened + recent.reopened, reopened: recent.reopened, resolved: recent.resolved }
      : null,
    reach: o ? { value: reachable, restricted } : null,
  }
})

function bars(items: Schemas['SummaryItem'][], label: (v: string) => string, link: (v: string) => Partial<FindingFilters> | null, extra: Partial<SeverityBarItem> = {}): SeverityBarItem[] {
  return items.map((i) => {
    const filters = i.value ? link(i.value) : null
    return {
      key: i.value || '(none)',
      label: label(i.value),
      severities: counts(i.severities),
      total: i.total,
      to: filters ? list(filters) : null,
      muted: !i.value,
      ...extra,
    }
  })
}

const accounts = computed<SeverityBarItem[]>(() =>
  (data.value?.by_account?.items ?? []).map((a) => ({
    key: String(a.connection_id),
    label: a.value,
    severities: counts(a.severities),
    total: a.total,
    to: list({ connection: [a.connection_id] }),
    dot: `var(--provider-${a.provider})`,
  })),
)
const categories = computed(() =>
  bars(data.value?.by_category?.items ?? [], (v) => (v ? categoryLabel(v) : 'No category'), (v) => ({ category: [v] })),
)
const services = computed(() =>
  bars(data.value?.by_service?.items ?? [], (v) => v || 'No service', (v) => ({ service: [v] }), { mono: true }),
)
const regions = computed(() =>
  bars(data.value?.by_region?.items ?? [], (v) => regionLabel(v), (v) => ({ region: [v] }), { mono: true }),
)

const REACH_WORD: Record<FindingReach, string> = {
  confirmed: 'Reachable',
  restricted: 'Restricted',
  unknown: 'Unknown',
  not_covered: 'Not checked',
}
const reach = computed(() =>
  bars(
    data.value?.reach ?? [],
    (v) => REACH_WORD[v as FindingReach] ?? v,
    (v) => ({ reach: [v as FindingReach] }),
  ).map((r) => ({ ...r, muted: false })),
)

const AGE: Record<string, [string, string]> = {
  under_30_days: ['Under 30 days', '<30d'],
  '30_to_90_days': ['30–90 days', '30–90d'],
  '90_to_180_days': ['90–180 days', '90–180d'],
  '180_to_365_days': ['180–365 days', '180–365d'],
  over_a_year: ['Over a year', '>1y'],
}
const ages = computed<SeverityColumn[]>(() =>
  (data.value?.by_age ?? []).map((a) => ({
    key: a.key,
    label: AGE[a.key]?.[0] ?? a.key,
    short: AGE[a.key]?.[1] ?? a.key,
    severities: counts(a.severities),
    total: a.total,
    to: list({ firstSeenFrom: a.first_seen_from ?? '', firstSeenTo: a.first_seen_to ?? '' }),
  })),
)

const topChecks = computed<SeverityBarItem[]>(() =>
  (checks.data.value?.items ?? []).map((g) => {
    const severity = (SEVERITIES as readonly string[]).includes(g.severity) ? (g.severity as Severity) : 'informational'
    const severities = Object.fromEntries(SEVERITIES.map((s) => [s, s === severity ? g.findings : 0])) as Record<Severity, number>
    const tool = (['prowler', 'cloudfox'] as Tool[]).find((t) => t === g.tool)
    return {
      key: `${g.tool}:${g.check_id}`,
      label: g.title || g.check_id,
      severities,
      total: g.findings,
      to: list({ check: [g.check_id], tool: tool ? [tool] : [] }),
      tag: severity,
      sub: `${g.check_id} · fails in ${int(g.connections)} account${g.connections === 1 ? '' : 's'}`,
    }
  }),
)
const moreChecks = computed(() => Math.max(0, (checks.data.value?.total ?? 0) - TOP))

const flowWeeks = computed(() => data.value?.weeks ?? [])
const noHistory = computed(() => flowWeeks.value.every((w) => w.opened == null))

function total(items: SeverityBarItem[]): number {
  return items.reduce((n, i) => n + i.total, 0)
}

const connectionOptions = computed(() => props.connections ?? [])
</script>

<template>
  <div class="summary">
    <div class="head">
      <div class="field">
        <label class="lbl" for="s-account">Account</label>
        <select id="s-account" class="select account" :value="String(connectionId)" @change="emit('selectConnection', Number(($event.target as HTMLSelectElement).value))">
          <option value="0">All connections</option>
          <option v-for="c in connectionOptions" :key="c.id" :value="String(c.id)">{{ c.name }}</option>
        </select>
      </div>
      <span class="through">
        <template v-if="data?.data_through">Data through <span class="mono strong">{{ data.data_through }}</span></template>
        <template v-else-if="data">No scan yet</template>
      </span>
    </div>
    <p class="cap scope">Open, failing findings from Prowler and CloudFox, muted ones left out. Each number opens the list it counts.</p>
    <ul class="legend" aria-label="Severity colours">
      <li v-for="s in SEVERITIES" :key="s"><span class="dot mark-dot" :style="{ '--series': SEVERITY_COLOR[s] }" aria-hidden="true"></span>{{ SEVERITY_LABEL[s] }}</li>
    </ul>

    <AlertBanner v-if="summary.error.value && !data" kind="fail">
      The summary didn't load: {{ summary.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="summary.reload()">Retry</button></template>
    </AlertBanner>

    <template v-else>
      <!-- Four tiles: CatherIs Platform's stat tiles (design-system.md, Card → Stat tile). -->
      <section aria-label="Key numbers" class="stat-grid">
        <template v-if="data">
          <div class="stat-card tile">
            <div class="stat-label"><span>Open misconfigurations</span></div>
            <b class="stat-value" :class="{ none: !tiles.open }">{{ tiles.open?.value ?? '—' }}</b>
            <span class="stat-sub">{{ tiles.open?.sub ?? noScan }}</span>
            <RouterLink v-if="tiles.open" class="drill-link" :to="list()" :aria-label="`Open misconfigurations: ${tiles.open.value}. Show in list`">
              Show in list<AppIcon name="chevron" :size="14" :stroke="2" />
            </RouterLink>
          </div>
          <div class="stat-card tile" :style="{ '--tone': 'var(--sev-critical)' }">
            <div class="stat-label"><span>Critical + high</span></div>
            <b class="stat-value" :class="{ none: !tiles.severe }" :style="tiles.severe ? { color: 'var(--sev-critical-text)' } : undefined">{{ tiles.severe?.value ?? '—' }}</b>
            <template v-if="tiles.severe">
              <span class="meter mark-track" aria-hidden="true">
                <span class="seg mark-bar" :style="{ width: `${tiles.severe.widths[0]}%`, '--series': 'var(--sev-critical)' }"></span>
                <span class="seg mark-bar" :style="{ width: `${tiles.severe.widths[1]}%`, '--series': 'var(--sev-high)' }"></span>
              </span>
              <span class="stat-sub">
                <span :style="{ color: SEVERITY_TEXT.critical }">Critical {{ int(tiles.severe.critical) }}</span> ·
                <span :style="{ color: SEVERITY_TEXT.high }">High {{ int(tiles.severe.high) }}</span>
              </span>
              <RouterLink class="drill-link" :to="list({ severity: ['critical', 'high'] })" :aria-label="`Critical and high: ${tiles.severe.value}. Show in list`">
                Show in list<AppIcon name="chevron" :size="14" :stroke="2" />
              </RouterLink>
            </template>
            <span v-else class="stat-sub">{{ noScan }}</span>
          </div>
          <div class="stat-card tile">
            <div class="stat-label"><span>Last 30 days</span></div>
            <b v-if="tiles.recent" class="stat-value">
              <span :style="{ color: 'var(--delta-worse)' }">+{{ int(tiles.recent.opened) }}</span>&thinsp;<span :style="{ color: 'var(--delta-better)' }">−{{ int(tiles.recent.resolved) }}</span>
              <span class="sr-only">: {{ int(tiles.recent.opened) }} opened, {{ int(tiles.recent.resolved) }} resolved, {{ int(tiles.recent.reopened) }} reopened in the last 30 days</span>
            </b>
            <b v-else class="stat-value none">—</b>
            <span class="stat-sub">{{ tiles.recent ? `opened · resolved · ${int(tiles.recent.reopened)} of them reopened` : 'No history yet' }}</span>
            <a v-if="tiles.recent" class="drill-link" href="#flow">See weekly trend<AppIcon name="chevron" :size="14" :stroke="2" /></a>
          </div>
          <div class="stat-card tile" :style="{ '--tone': tiles.reach?.value ? 'var(--sev-high)' : undefined }">
            <div class="stat-label"><span>Internet reachable</span></div>
            <b class="stat-value" :class="{ none: !tiles.reach }">{{ tiles.reach ? int(tiles.reach.value) : '—' }}</b>
            <span class="stat-sub">{{ tiles.reach ? `Argus confirmed traffic can arrive · ${int(tiles.reach.restricted)} restricted` : noScan }}</span>
            <RouterLink v-if="tiles.reach" class="drill-link" :to="list({ reach: ['confirmed'] })" :aria-label="`Internet reachable: ${int(tiles.reach.value)}. Show in list`">
              Show in list<AppIcon name="chevron" :size="14" :stroke="2" />
            </RouterLink>
          </div>
        </template>
        <template v-else>
          <div v-for="n in 4" :key="n" class="stat-card skeleton"></div>
        </template>
      </section>

      <div v-if="!data" class="grid" aria-busy="true">
        <section v-for="n in 4" :key="n" class="card panel"><div class="panel-body loading"><div v-for="m in 5" :key="m" class="skeleton sk-44"></div></div></section>
      </div>

      <section v-else-if="!scanned" class="card panel">
        <EmptyState icon="flag" title="Nothing to summarise yet." text="The summary fills in after the first Prowler or CloudFox scan.">
          <RouterLink class="btn btn-ghost" :to="{ name: 'runs' }">Go to Runs</RouterLink>
        </EmptyState>
      </section>

      <template v-else>
        <div class="grid">
          <section v-if="connectionId === 0" class="card panel" aria-labelledby="s-accounts">
            <div class="panel-h"><h2 id="s-accounts" class="h2">Most misconfigured accounts</h2><span class="mono count">{{ int(total(accounts)) }}</span></div>
            <div class="panel-body fit">
              <SeverityBars v-if="accounts.length" :items="accounts" />
              <p v-else class="none-open">No open misconfigurations.</p>
              <p v-if="data.by_account?.more" class="more cap">+ {{ int(data.by_account.more) }} more · <RouterLink class="drill-link" :to="list()">Show all in list</RouterLink></p>
            </div>
          </section>

          <section class="card panel" aria-labelledby="s-categories">
            <div class="panel-h"><h2 id="s-categories" class="h2">By category</h2></div>
            <div class="panel-body fit">
              <SeverityBars v-if="categories.length" :items="categories" />
              <p v-else class="none-open">No open misconfigurations.</p>
              <p v-if="data.by_category?.more" class="more cap">+ {{ int(data.by_category.more) }} more · <RouterLink class="drill-link" :to="list()">Show all in list</RouterLink></p>
              <p class="cap">A finding can have several categories, so these add up to more than the total.</p>
            </div>
          </section>

          <section class="card panel" aria-labelledby="s-checks">
            <div class="panel-h"><h2 id="s-checks" class="h2">Top failing checks</h2></div>
            <div class="panel-body fit">
              <AlertBanner v-if="checks.error.value" kind="fail">
                Checks didn't load: {{ checks.error.value }}
                <template #action><button type="button" class="btn btn-secondary btn-sm" @click="checks.reload()">Retry</button></template>
              </AlertBanner>
              <div v-else-if="!checks.data.value" aria-busy="true" class="loading"><div v-for="m in 5" :key="m" class="skeleton sk-44"></div></div>
              <SeverityBars v-else-if="topChecks.length" :items="topChecks" noun="findings" wrap />
              <p v-else class="none-open">No open misconfigurations.</p>
              <p v-if="moreChecks" class="more cap">+ {{ int(moreChecks) }} more · <RouterLink class="drill-link" :to="list({}, 'checks')">Show all by check</RouterLink></p>
            </div>
          </section>

          <section class="card panel" aria-labelledby="s-age">
            <div class="panel-h"><h2 id="s-age" class="h2">How long they've been open</h2></div>
            <div class="panel-body">
              <SeverityColumns :columns="ages" />
              <p class="cap">Counted from the day each was first seen.</p>
            </div>
          </section>

          <section class="card panel" aria-labelledby="s-services">
            <div class="panel-h"><h2 id="s-services" class="h2">By service</h2></div>
            <div class="panel-body fit">
              <SeverityBars v-if="services.length" :items="services" />
              <p v-else class="none-open">No open misconfigurations.</p>
              <p v-if="data.by_service?.more" class="more cap">+ {{ int(data.by_service.more) }} more · <RouterLink class="drill-link" :to="list()">Show all in list</RouterLink></p>
            </div>
          </section>

          <section class="card panel" aria-labelledby="s-regions">
            <div class="panel-h"><h2 id="s-regions" class="h2">By region</h2></div>
            <div class="panel-body fit">
              <SeverityBars v-if="regions.length" :items="regions" />
              <p v-else class="none-open">No open misconfigurations.</p>
              <p v-if="data.by_region?.more" class="more cap">+ {{ int(data.by_region.more) }} more · <RouterLink class="drill-link" :to="list()">Show all in list</RouterLink></p>
            </div>
          </section>
        </div>

        <div class="grid flow-row">
          <section id="flow" class="card panel" aria-labelledby="s-flow" tabindex="-1">
            <div class="panel-h"><h2 id="s-flow" class="h2">Opened vs resolved, last 12 weeks</h2></div>
            <div class="panel-body">
              <p v-if="noHistory" class="none-open">No history yet: weeks fill in from the first scan after this release.</p>
              <WeeklyFlow v-else :weeks="flowWeeks" noun="misconfigurations" />
            </div>
          </section>
          <section class="card panel" aria-labelledby="s-reach">
            <div class="panel-h"><h2 id="s-reach" class="h2">Internet reach (Argus)</h2></div>
            <div class="panel-body fit">
              <SeverityBars :items="reach" />
              <p class="cap">Exposure findings judged against the configuration Steampipe recorded.</p>
            </div>
          </section>
        </div>
      </template>
    </template>
  </div>
</template>

<style scoped>
.summary {
  display: flex;
  flex-direction: column;
  gap: var(--s-14);
}

.head {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--s-12);
}

.account {
  min-width: 220px;
}

.through {
  margin-left: auto;
  font-size: 12px;
  color: var(--text-3);
}

.strong {
  color: var(--text);
}

.scope {
  margin: 0;
  max-width: 90ch;
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-14);
  margin: 0;
  padding: 0;
  list-style: none;
  font-size: 12px;
  color: var(--text-2);
}

.legend li {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.legend .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.tile {
  gap: var(--s-4);
}

.stat-value.none {
  color: var(--text-3);
}

.meter {
  display: flex;
  gap: 1px;
  height: 8px;
  margin: var(--s-6) 0 var(--s-4);
  overflow: hidden;
  border-radius: 3px;
}

.meter .seg {
  height: 100%;
}

.drill-link {
  margin-top: var(--s-8);
  align-self: flex-start;
}

.grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--s-14);
}

.flow-row {
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
}

@media (max-width: 1150px) {
  .grid,
  .flow-row {
    grid-template-columns: minmax(0, 1fr);
  }
}

.panel-h {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--s-12);
}

.count {
  font-size: 13px;
  color: var(--text-2);
}

.panel-body {
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
}

.fit {
  container-type: inline-size;
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.none-open {
  margin: 0;
  font-size: 13px;
  color: var(--text-2);
}

.more {
  margin: 0;
}

.more .drill-link {
  margin-top: 0;
  display: inline-flex;
}

p.cap {
  margin: 0;
}
</style>
