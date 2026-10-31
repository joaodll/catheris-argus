<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import FilterBar from '@/components/FilterBar.vue'
import LiveIndicator from '@/components/LiveIndicator.vue'
import PageHeader from '@/components/PageHeader.vue'
import RefreshButton from '@/components/RefreshButton.vue'
import SortHeader from '@/components/SortHeader.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { COLLECTORS, type Collector } from '@/tools'
import { duration, elapsed, relative, utc, utcTime } from '@/format'
import { commandLabel, encryptionLabel, partialReason, partialTables, partialTablesNote, regionsLabel, shortRunId, storedWithoutKms, triggerLabel } from './runNotes'

type Tool = Collector
type Status = 'complete' | 'partial' | 'failed' | 'running'
const PAGE = 20

const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const connectionId = ref<number | null>(null)
const tool = ref<Tool | null>(null)
const status = ref<Status | null>(null)
const missingPermissions = ref(false)

// A run becomes a row below only when it ends; until then it is a claimed request.
const queue = useResource(() => unwrap(api.GET('/api/v1/run-requests')), { refreshMs: 10_000 })
const running = computed(() =>
  (queue.data.value?.items ?? []).filter(
    (r) =>
      r.status === 'claimed' &&
      (connectionId.value == null || r.connection_id === connectionId.value) &&
      (tool.value == null || r.tool === tool.value),
  ),
)
const showRunning = computed(() => (status.value == null || status.value === 'running') && !missingPermissions.value)
// The header counts everything running, whatever the filters; 0 while loading or after an error.
const runningCount = computed(() =>
  queue.error.value ? 0 : (queue.data.value?.items ?? []).filter((r) => r.status === 'claimed').length,
)
// Elapsed times tick every second while something runs.
const now = ref(Date.now())
let ticker: ReturnType<typeof setInterval> | undefined
watch(
  () => running.value.length > 0,
  (any) => {
    clearInterval(ticker)
    ticker = any ? setInterval(() => (now.value = Date.now()), 1000) : undefined
  },
  { immediate: true },
)
onBeforeUnmount(() => clearInterval(ticker))
const HEARTBEAT_LATE_MS = 2 * 60 * 1000
function heartbeatLate(iso: string | null | undefined): boolean {
  return Boolean(iso) && now.value - new Date(iso as string).getTime() > HEARTBEAT_LATE_MS
}
// A run that just ended appears in the table: reload the page shown. Only a request leaving the
// queue counts, not a filter hiding one (the filters reload on their own).
let runningBefore = new Set<number>()
watch(
  () => queue.data.value,
  (data) => {
    const now = new Set((data?.items ?? []).filter((r) => r.status === 'claimed').map((r) => r.id))
    const ended = [...runningBefore].some((id) => !now.has(id))
    runningBefore = now
    if (ended) void load(page.value)
  },
)

const runs = shallowRef<Schemas['RunOut'][]>([])
const total = ref(0)
const page = ref(1)
const order = ref<'started_desc' | 'started_asc'>('started_desc')
const filtered = computed(() => Boolean(connectionId.value || tool.value || status.value || missingPermissions.value))
const table = ref<HTMLElement | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
const open = ref<Set<number>>(new Set())
let generation = 0

async function load(target: number): Promise<void> {
  const mine = ++generation
  loading.value = true
  error.value = null
  try {
    const result = await unwrap(
      api.GET('/api/v1/runs', {
        params: {
          query: {
            limit: PAGE,
            offset: (target - 1) * PAGE,
            order: order.value,
            connection_id: connectionId.value,
            tool: tool.value,
            status: status.value,
            missing_permissions: missingPermissions.value,
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
    runs.value = result.items
    total.value = result.total
    page.value = target
  } catch (err) {
    if (mine === generation) error.value = err instanceof ApiError ? err.message : 'Runs did not load.'
  } finally {
    if (mine === generation) loading.value = false
  }
}

// A filter or the order changes the list: back to page 1.
watch([connectionId, tool, status, missingPermissions, order], () => void load(1), { immediate: true })

async function goTo(target: number): Promise<void> {
  await load(target)
  await nextTick()
  table.value?.focus() // the new rows are announced
}

function toggleOrder(): void {
  order.value = order.value === 'started_desc' ? 'started_asc' : 'started_desc'
}

function toggle(id: number): void {
  const next = new Set(open.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  open.value = next
}

/** A click on a row opens it, except on its own controls or while selecting text (as on Findings). */
function onRowClick(event: MouseEvent, id: number): void {
  if ((event.target as Element).closest('a, button, input, select, label, summary')) return
  if (window.getSelection()?.toString()) return
  toggle(id)
}

function clearFilters(): void {
  connectionId.value = null
  tool.value = null
  status.value = null
  missingPermissions.value = false
}

// The runs shown and what is running now, on demand.
function refresh(): Promise<unknown> {
  return Promise.all([load(page.value), queue.reload()])
}

function fromSelect(value: string): string | null {
  return value === '' ? null : value
}
</script>

<template>
  <PageHeader title="Runs">
    Partial and failed runs never resolve findings.
    <template #actions><LiveIndicator :count="runningCount" /><RefreshButton :reload="refresh" /></template>
  </PageHeader>
  <section v-if="showRunning && running.length" class="card running-card" aria-labelledby="running-h">
    <div class="card-head">
      <h2 id="running-h" class="h2">Running now <span class="mono count">{{ running.length }}</span></h2>
    </div>
    <ul class="running-list">
      <li v-for="r in running" :key="r.id">
        <span class="who">
          <StatusBadge status="running" />
          <ToolChip :tool="r.tool" />
          <span class="conn" :title="r.connection">{{ r.connection }}</span>
          <span v-if="r.attempt > 1" class="cap">retry {{ r.attempt }} of 3</span>
        </span>
        <span class="when">
          <span class="cap">started {{ r.claimed_at ? relative(r.claimed_at, now) : '' }}</span>
          <span class="mono elapsed">{{ elapsed(r.claimed_at, now) }}</span>
          <span v-if="r.heartbeat_at && heartbeatLate(r.heartbeat_at)" class="late">
            <AppIcon name="warning" :size="12" :stroke="2.4" />no heartbeat for {{ relative(r.heartbeat_at, now).replace(' ago', '') }}
          </span>
          <span v-else-if="r.heartbeat_at" class="cap">heartbeat {{ relative(r.heartbeat_at, now) }}</span>
        </span>
      </li>
    </ul>
  </section>
  <FilterBar label="Filter runs" :active="filtered" @clear="clearFilters">
    <div class="field">
      <label class="lbl" for="f-conn">Connection</label>
      <select id="f-conn" class="select" :value="connectionId ?? ''" @change="connectionId = Number(fromSelect(($event.target as HTMLSelectElement).value)) || null">
        <option value="">All connections</option>
        <option v-for="c in connections.data.value ?? []" :key="c.id" :value="c.id">{{ c.name }}</option>
      </select>
    </div>
    <div class="field">
      <label class="lbl" for="f-tool">Tool</label>
      <select id="f-tool" class="select" :value="tool ?? ''" @change="tool = fromSelect(($event.target as HTMLSelectElement).value) as Tool | null">
        <option value="">All tools</option>
        <option v-for="c in COLLECTORS" :key="c.id" :value="c.id">{{ c.name }}</option>
      </select>
    </div>
    <div class="field">
      <label class="lbl" for="f-status">Status</label>
      <select id="f-status" class="select" :value="status ?? ''" @change="status = fromSelect(($event.target as HTMLSelectElement).value) as Status | null">
        <option value="">Any status</option>
        <option value="complete">Complete</option>
        <option value="partial">Partial</option>
        <option value="failed">Failed</option>
        <option value="running">Running</option>
      </select>
    </div>
    <label class="check">
      <input v-model="missingPermissions" type="checkbox">
      Missing permissions only
    </label>
  </FilterBar>

  <section class="card stack" aria-labelledby="runs-h">
    <div class="card-head">
      <div class="titles">
        <h2 id="runs-h" class="h2">Every collector run</h2>
        <span class="cap">{{ order === 'started_desc' ? 'Newest first.' : 'Oldest first.' }} Times are UTC.</span>
      </div>
    </div>


    <AlertBanner v-if="error" kind="fail">
      Runs didn't load: {{ error }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="load(page)">Retry</button></template>
    </AlertBanner>
    <div v-else-if="loading && runs.length === 0" aria-busy="true" class="loading"><div v-for="n in 5" :key="n" class="skeleton sk-48"></div></div>
    <EmptyState
      v-else-if="runs.length === 0 && filtered"
      icon="info"
      title="No runs match these filters."
    >
      <button type="button" class="btn btn-secondary" @click="clearFilters">Clear filters</button>
    </EmptyState>
    <EmptyState v-else-if="runs.length === 0" icon="clock" title="No runs yet." text="Add a connection, or start one from Schedules." />
    <div v-else ref="table" class="table-wrap table-fit" tabindex="-1" aria-labelledby="runs-h">
      <table class="table stackable stack-narrow dense runs-table">
        <thead>
          <tr>
            <SortHeader
              label="Started (UTC)"
              :direction="order === 'started_desc' ? 'desc' : 'asc'"
              desc-text="newest first"
              asc-text="oldest first"
              @toggle="toggleOrder"
            /><th scope="col">Connection</th><th scope="col">Tool</th><th scope="col">Scan date</th><th scope="col">Status</th>
            <th scope="col" class="right">Duration</th><th scope="col">Regions</th><th scope="col"><span class="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="r in runs" :key="r.id">
            <tr class="row" :class="{ expanded: open.has(r.id) }" @click="onRowClick($event, r.id)">
              <td data-label="Started">
                <span class="mono" :title="utc(r.started_at)">{{ r.started_at.slice(0, 10) }} {{ utcTime(r.started_at) }}</span>
                <span class="sub mono" :title="r.run_uid">{{ shortRunId(r.run_uid) }}</span>
              </td>
              <td data-label="Connection">{{ r.connection }}</td>
              <td data-label="Tool"><span class="tool"><ToolChip :tool="r.tool" /><span class="mono version">{{ r.tool_version }}</span></span></td>
              <td data-label="Scan date"><span class="tool"><span class="mono">{{ r.snapshot_date }}</span><span v-if="r.source === 'synthetic'" class="chip">Synthetic</span></span></td>
              <td data-label="Status">
                <span class="status">
                  <StatusBadge :status="r.status" />
                  <StatusBadge
                    v-if="r.denied_actions.length"
                    status="warning"
                    :label="`${r.denied_actions.length} permission${r.denied_actions.length === 1 ? '' : 's'} missing`"
                  />
                  <StatusBadge v-if="storedWithoutKms(r)" status="warning" label="No KMS" />
                </span>
                <span v-if="r.exit_code != null && r.exit_code !== 0" class="sub mono bad">Exit {{ r.exit_code }}</span>
              </td>
              <td data-label="Duration" class="right">
                <span class="mono">{{ duration(r.duration_seconds) }}</span>
                <span v-if="r.throttle_events > 0" class="sub throttled" :title="`Throttled ${r.throttle_events} time${r.throttle_events === 1 ? '' : 's'}`"><AppIcon name="warning" :size="12" :stroke="2.2" /><span class="mono">{{ r.throttle_events }}</span> throttled</span>
              </td>
              <td data-label="Regions"><span :title="r.region_scope.join(', ')">{{ regionsLabel(r) }}</span></td>
              <td data-label="">
                <button type="button" class="icon-btn chev" :aria-expanded="open.has(r.id)" :aria-label="`${open.has(r.id) ? 'Hide' : 'Show'} details of run ${shortRunId(r.run_uid)}`" @click="toggle(r.id)">
                  <AppIcon name="chevron" :size="16" :stroke="2" />
                </button>
              </td>
            </tr>
            <tr v-if="open.has(r.id)" class="detail">
              <td colspan="8">
                <div class="detail-body">
                  <AlertBanner v-if="r.status === 'partial' && partialTables(r).length" kind="warn">
                    {{ partialTablesNote(r.tool, partialTables(r).length) }}
                    <details class="tables">
                      <summary>Show the {{ partialTables(r).length }} table{{ partialTables(r).length === 1 ? '' : 's' }}</summary>
                      <ul class="denied mono">
                        <li v-for="t in partialTables(r)" :key="t">{{ t }}</li>
                      </ul>
                    </details>
                  </AlertBanner>
                  <AlertBanner v-else-if="r.status === 'partial'" kind="warn">
                    Partial: {{ partialReason(r) }}. Partial runs never resolve
                    findings, and are not retried.
                  </AlertBanner>
                  <AlertBanner v-else-if="r.status === 'failed'" kind="fail">Failed: nothing from this run changes findings.</AlertBanner>
                  <AlertBanner v-if="r.denied_actions.length" kind="warn">
                    <strong>Missing from the role.</strong> The scanning identity was denied these actions, so their data is missing
                    from this run. Add them to the role or permission set (read actions only), then run again.
                    <ul class="denied mono">
                      <li v-for="a in r.denied_actions" :key="a">{{ a }}</li>
                    </ul>
                  </AlertBanner>
                  <AlertBanner v-if="r.refused_actions.length || r.refused_tables.length" kind="info">
                    <strong>Refused by a policy.</strong> A resource's own policy refused the scanner (a KMS key whose key policy does
                    not hand access to IAM, a service the account does not own), or an explicit Deny did: the scanner role's own, which
                    keeps secret values, code, log content and API keys out of reach on purpose, or a service control policy. Do not add
                    these to the role. Their data was carried forward and the run is not partial because of it.
                    <ul v-if="r.refused_actions.length" class="denied mono">
                      <li v-for="a in r.refused_actions" :key="a">{{ a }}</li>
                    </ul>
                    <details v-if="r.refused_tables.length" class="tables">
                      <summary>Show the {{ r.refused_tables.length }} table{{ r.refused_tables.length === 1 ? '' : 's' }}</summary>
                      <ul class="denied mono">
                        <li v-for="t in r.refused_tables" :key="t">{{ t }}</li>
                      </ul>
                    </details>
                  </AlertBanner>
                  <AlertBanner v-if="r.not_applicable_tables.length" kind="info">
                    <strong>Not used in this account.</strong> {{ r.not_applicable_tables.length }}
                    table{{ r.not_applicable_tables.length === 1 ? '' : 's' }} belong to services this account does not use, or that
                    answer only in another account (Organizations outside the management account). There is nothing to read, and the
                    run is not partial because of them.
                    <details class="tables">
                      <summary>Show the {{ r.not_applicable_tables.length }} table{{ r.not_applicable_tables.length === 1 ? '' : 's' }}</summary>
                      <ul class="denied mono">
                        <li v-for="t in r.not_applicable_tables" :key="t">{{ t }}</li>
                      </ul>
                    </details>
                  </AlertBanner>
                  <AlertBanner v-if="storedWithoutKms(r)" kind="warn">
                    Raw output was stored with {{ encryptionLabel(r.raw_encryption ?? '') }}, not SSE-KMS. It can hold secret values
                    (Lambda environment, EC2 user data, CloudFox env-vars); SSE-KMS adds a key policy and a decrypt audit trail. Set
                    the bucket's default encryption to SSE-KMS.
                  </AlertBanner>
                  <dl class="facts">
                    <div class="wide"><dt class="lbl">Started by</dt><dd>{{ triggerLabel(r.trigger) }}</dd></div>
                    <div><dt class="lbl">Run ID</dt><dd class="mono path">{{ r.run_uid }}</dd></div>
                    <div><dt class="lbl">Exit code</dt><dd class="mono">{{ r.exit_code ?? 'None' }}</dd></div>
                    <div><dt class="lbl">Throttling</dt><dd class="mono">{{ r.throttle_events }}</dd></div>
                    <div><dt class="lbl">Source</dt><dd>{{ r.source === 'synthetic' ? 'Synthetic' : r.source }}</dd></div>
                    <div><dt class="lbl">Finished</dt><dd class="mono">{{ utc(r.finished_at) }}</dd></div>
                    <div><dt class="lbl">Ingested</dt><dd class="mono">{{ utc(r.ingested_at) }}</dd></div>
                    <div class="wide"><dt class="lbl">Raw output</dt><dd class="mono path">{{ r.raw_path || 'Not archived: the run ended first.' }}</dd></div>
                    <div class="wide"><dt class="lbl">Command</dt><dd :class="r.command ? 'mono path' : ''">{{ commandLabel(r) }}</dd></div>
                  </dl>
                  <div class="field">
                    <span class="lbl">Log tail</span>
                    <pre class="code log" tabindex="0" :aria-label="`Log tail of run ${shortRunId(r.run_uid)}`">{{ r.log_tail || 'No log output.' }}</pre>
                  </div>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
    <AppPagination v-if="runs.length" :total="total" :page="page" :limit="PAGE" @change="goTo" />
  </section>
</template>

<style scoped>
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

.tool {
  display: inline-flex;
  gap: var(--s-6);
  align-items: center;
}

.path {
  overflow-wrap: anywhere;
}

.version {
  font-size: 11px;
  color: var(--text-3);
}

.bad {
  color: var(--status-fail);
}

.throttled {
  display: inline-flex;
  gap: var(--s-4);
  align-items: center;
  color: var(--status-warn);
}

.chev :deep(svg) {
  transition: transform var(--ease);
}

.chev[aria-expanded='true'] :deep(svg) {
  transform: rotate(90deg);
}

.table tr.detail > td,
.table tr.detail:hover > td {
  background: var(--tile);
}

/* A row opens on a click anywhere outside its links and buttons, as on Findings. The table fits
   its panel (.table-fit): Run ID sits under Started, Exit under Status, throttling under
   Duration, and the rows stack when the panel is narrower than 900 px. */
.runs-table tr.row {
  cursor: pointer;
}

.runs-table tr.row.expanded > td {
  background: var(--surface-raised);
}

.sub {
  display: flex;
  align-items: center;
  gap: var(--s-4);
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
}

td.right .sub {
  justify-content: flex-end;
}

.sub.bad {
  color: var(--status-fail);
}

.sub.throttled {
  color: var(--status-warn);
}

.runs-table tr.detail > td {
  padding: 0;
}

.detail-body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
  padding: var(--s-12) var(--s-16) var(--s-16);
}

/* A log line never widens the page: long lines wrap (ARNs and URLs break anywhere). */
.log {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

@container (max-width: 900px) {
  .runs-table tr.detail > td {
    display: block;
  }

  .detail-body {
    padding: var(--s-4) 0 var(--s-8);
  }

  td.right .sub {
    justify-content: flex-start;
  }
}

.facts {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--s-10) var(--s-20);
  font-size: 13px;
}

.facts dd {
  margin: 2px 0 0;
}

.facts .wide {
  grid-column: 1 / -1;
}

.status {
  display: inline-flex;
  gap: var(--s-6);
  align-items: center;
  flex-wrap: wrap;
}

.running-card {
  border-left: 3px solid var(--status-run);
  padding: var(--s-16) var(--s-20);
}

.running-card .count {
  color: var(--status-run);
  font-size: 14px;
  margin-left: var(--s-6);
}

.running-list {
  margin: var(--s-8) 0 0;
  padding: 0;
  list-style: none;
}

.running-list li {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-6) var(--s-16);
  min-height: 44px;
  padding: var(--s-6) 0;
  border-top: 1px solid var(--border);
  font-size: 13px;
}

.running-list li:first-child {
  border-top: 0;
}

.who,
.when {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-10);
  min-width: 0;
}

.conn {
  max-width: 32ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text);
}

.elapsed {
  color: var(--text-2);
}

.late {
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
  color: var(--status-warn);
  font-size: 12px;
}

.tables summary {
  margin-top: var(--s-6);
  cursor: pointer;
  font-size: 12px;
}

.denied {
  margin: var(--s-6) 0 0;
  padding-left: var(--s-20);
  font-size: 12px;
}

.runs-table td {
  white-space: nowrap;
}

.runs-table tr.detail > td {
  white-space: normal;
}
</style>
