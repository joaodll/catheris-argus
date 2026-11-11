<script setup lang="ts">
/**
 * Operate -> Reports (ADR-0047; palace frontend/08ff3c8d): exports of Misconfigurations and
 * Vulnerabilities, built by the worker. Operator and Admin only; an Operator sees their own.
 */
import { computed, onScopeDispose, ref, watch } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import PageHeader from '@/components/PageHeader.vue'
import RefreshButton from '@/components/RefreshButton.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useResource } from '@/composables/useResource'
import { session } from '@/composables/useSession'
import { toast } from '@/composables/useToasts'
import ReportModal from './ReportModal.vue'
import { describe, fromStored } from './reportFilters'

type Report = Schemas['ReportOut']
const PAGE = 20
// While a report is queued or building, the list looks again this often.
const POLL_MS = 5_000
const page = ref(1)
const admin = computed(() => session.value?.role === 'admin')

const reports = useResource(
  () => unwrap(api.GET('/api/v1/reports', { params: { query: { limit: PAGE, offset: (page.value - 1) * PAGE } } })),
  { watch: [page] },
)
const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const items = computed(() => reports.data.value?.items ?? [])
const total = computed(() => reports.data.value?.total ?? 0)
const storage = computed(() => reports.data.value?.storage ?? null)
const busy = computed(() => items.value.filter((r) => r.status === 'queued' || r.status === 'building').length)
const atCap = computed(() => !!reports.data.value && !admin.value && busy.value >= reports.data.value.max_open)
const creating = ref(false)

let timer: number | undefined
watch(
  busy,
  (count) => {
    window.clearInterval(timer)
    timer = undefined
    if (count > 0) {
      timer = window.setInterval(() => {
        if (document.visibilityState === 'visible') void reports.reload()
      }, POLL_MS)
    }
  },
  { immediate: true },
)
onScopeDispose(() => window.clearInterval(timer))

function accountName(id: number): string {
  return connections.data.value?.find((c) => c.id === id)?.name ?? `#${id}`
}

function words(r: Report): string {
  return describe(fromStored(r.filters), accountName)
}

function kindName(r: Report): string {
  return r.kind === 'misconfigurations' ? 'Misconfigurations' : 'Vulnerabilities'
}

function when(iso: string): string {
  return `${iso.slice(0, 16).replace('T', ' ')} UTC`
}

function size(bytes: number | null | undefined): string {
  if (bytes == null) return ''
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function through(r: Report): string {
  const days = Object.values(r.data_through ?? {}).sort()
  return days.length ? `data through ${days[days.length - 1]}` : 'no scan yet'
}

function expiresIn(r: Report): string {
  if (!r.expires_at) return ''
  const hours = (Date.parse(r.expires_at) - Date.now()) / 3_600_000
  if (hours < 24) return 'Expires today'
  const days = Math.ceil(hours / 24)
  return `Expires in ${days} ${days === 1 ? 'day' : 'days'}`
}

/** A CSV holds rows; a PDF covers findings and lists some of their resources (ADR-0047). */
function fileLine(r: Report): string {
  const n = (r.row_count ?? 0).toLocaleString('en-US')
  if (r.format === 'csv') return `${n} rows`
  return r.truncated ? `${n} findings, some listed` : `${n} findings, all listed`
}

function badge(r: Report): string {
  return r.expired ? 'expired' : r.status
}

async function onRequested(id: number): Promise<void> {
  creating.value = false
  page.value = 1
  await reports.reload()
  toast(`Report #${id} requested. It appears here when it is ready.`)
}
</script>

<template>
  <PageHeader title="Reports">
    Exports of Misconfigurations and Vulnerabilities<template v-if="reports.data.value">, kept {{ reports.data.value.expiry_days }} days</template>.
    <template #actions><RefreshButton :reload="reports.reload" /></template>
  </PageHeader>

  <AlertBanner v-if="storage === 'local'" class="note">
    Reports on this install cover Demo connections only. Real accounts get reports on Kubernetes, from the raw-output bucket.
  </AlertBanner>

  <section class="card panel" aria-labelledby="rep-h">
    <div class="panel-h">
      <div class="titles">
        <h2 id="rep-h" class="h2">Reports</h2>
        <span class="cap">{{ admin ? "Newest first. An Admin sees everyone's." : 'Newest first. Only your own.' }}</span>
      </div>
      <button
        v-if="storage === 'local'"
        type="button"
        class="btn btn-primary"
        :aria-disabled="atCap ? 'true' : undefined"
        :title="atCap ? `You have ${busy} reports being built` : undefined"
        @click="atCap || (creating = true)"
      >
        <AppIcon name="plus" :size="16" :stroke="2.2" />New report
      </button>
    </div>

    <div v-if="reports.error.value" class="panel-body">
      <AlertBanner kind="fail">
        Reports didn't load: {{ reports.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="reports.reload">Retry</button></template>
      </AlertBanner>
    </div>
    <div v-else-if="!reports.data.value" aria-busy="true" class="panel-body loading"><div v-for="n in 3" :key="n" class="skeleton sk-48"></div></div>
    <div v-else-if="storage === 'off'" class="panel-body">
      <EmptyState
        icon="info"
        title="Reports are not available on this install yet."
        text="They need the reports folder of the raw-output bucket, which comes in a later release."
      />
    </div>
    <div v-else-if="items.length === 0" class="panel-body">
      <EmptyState icon="report" title="No reports yet." text="Export a list from Misconfigurations or Vulnerabilities, or start one here.">
        <button type="button" class="btn btn-secondary" @click="creating = true">New report</button>
      </EmptyState>
    </div>
    <div v-else class="table-wrap table-fit">
      <table class="table stackable stack-narrow dense reports-table">
        <thead>
          <tr>
            <th scope="col">Report</th>
            <th v-if="admin" scope="col">Requested</th>
            <th scope="col">Status</th>
            <th scope="col">File</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in items" :key="r.id" :class="{ 'is-off': r.expired }">
            <td data-label="Report" class="report">
              <span class="kind">{{ kindName(r) }}</span>
              <span class="sub">{{ r.format.toUpperCase() }} · <span class="mono">#{{ r.id }}</span> · {{ words(r) }}</span>
              <span v-if="!admin" class="sub mono">{{ when(r.requested_at) }}</span>
            </td>
            <td v-if="admin" data-label="Requested">
              <span class="who">{{ r.requested_by }}</span>
              <span class="sub mono">{{ when(r.requested_at) }}</span>
            </td>
            <td data-label="Status">
              <span class="badges">
                <StatusBadge :status="badge(r)" />
                <StatusBadge v-if="r.truncated && r.row_count != null && r.format === 'csv'" status="warning" :label="`First ${r.row_count.toLocaleString('en-US')} rows`" />
              </span>
              <span v-if="r.status === 'failed' && r.error" class="error">{{ r.error }}</span>
            </td>
            <td data-label="File">
              <template v-if="r.status === 'ready'">
                <span class="mono rows">{{ fileLine(r) }}</span>
                <span class="sub">{{ size(r.size_bytes) }} · {{ through(r) }}</span>
                <span v-if="!r.expired" class="sub">{{ expiresIn(r) }}</span>
              </template>
              <span v-else class="sub">—</span>
            </td>
            <td data-label="" class="action">
              <a
                v-if="r.downloadable"
                class="btn btn-secondary btn-sm"
                :href="`/api/v1/reports/${r.id}/download`"
                download
                :aria-label="`Download report #${r.id}`"
              ><AppIcon name="download" :size="14" :stroke="2.2" />Download</a>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="items.length" class="panel-foot">
      <AppPagination :total="total" :page="page" :limit="PAGE" noun="report" @change="(p) => (page = p)" />
    </div>
  </section>

  <ReportModal v-if="creating" :connections="connections.data.value ?? []" @close="creating = false" @requested="onRequested" />
</template>

<style scoped>
.note {
  margin-bottom: var(--s-16);
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

.reports-table td {
  white-space: nowrap;
  vertical-align: top;
}

/* The report column takes what the others leave, and wraps. */
.reports-table td.report {
  width: 100%;
  white-space: normal;
}

.report,
.reports-table td {
  overflow-wrap: anywhere;
}

.report .sub,
.reports-table .sub {
  display: block;
}

.kind,
.who {
  display: block;
  font-size: 14px;
  font-weight: 600;
}

.badges {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-4);
}

.error {
  display: block;
  max-width: 280px;
  margin-top: var(--s-4);
  font-size: 12px;
  color: var(--text-2);
  white-space: normal;
}

.rows {
  display: block;
  font-size: 13px;
}

@media (max-width: 640px) {
  .action .btn {
    width: 100%;
    justify-content: center;
  }
}
</style>
