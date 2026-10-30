<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { toast } from '@/composables/useToasts'
import { relative, utc } from '@/format'

const TOOL_LABEL: Record<string, string> = { steampipe: 'Steampipe', prowler: 'Prowler', cloudfox: 'CloudFox' }

const queue = useResource(() => unwrap(api.GET('/api/v1/run-requests')), { refreshMs: 10_000 })
const updated = ref<string>('')
// The first page in claim order; `total` and `backfills` count everything waiting.
const items = computed(() => queue.data.value?.items ?? [])
const total = computed(() => queue.data.value?.total ?? 0)
const backfills = computed(() => queue.data.value?.backfills ?? [])
watch(queue.data, () => (updated.value = new Date().toISOString().slice(11, 19)))

// How many run now, for the page's live indicator (0 while loading or after an error).
// `canCancel`: an Operator or Admin; a Viewer reads the queue (ADR-0041).
const props = defineProps<{ canCancel: boolean }>()
const emit = defineEmits<{ running: [count: number] }>()
watch(
  () => (queue.error.value ? 0 : items.value.filter((r) => r.status === 'claimed').length),
  (count) => emit('running', count),
  { immediate: true },
)

function reason(r: Schemas['PendingRequest']): string {
  if (r.reason === 'backfill') return `Backfill ${r.snapshot_date ?? ''}`
  // A retry follows a failed run (see Runs for why); it waits until "Not before". A partial
  // run is not retried (argus_v8).
  if (r.reason === 'retry' || r.attempt > 1) return `Retry ${r.attempt} of 3 after a failed run`
  if (r.reason === 'manual') return 'Run now'
  if (r.reason === 'schedule') return 'Schedule'
  return r.reason
}

function notBefore(iso: string): string {
  return new Date(iso).getTime() <= Date.now() ? 'now' : utc(iso).slice(11)
}
/** The line under a row's status: a running run's heartbeat, a waiting one's start time. */
function statusLine(r: Schemas['PendingRequest']): string | null {
  if (r.status === 'claimed') return r.heartbeat_at ? `heartbeat ${relative(r.heartbeat_at)}` : null
  const at = notBefore(r.not_before)
  return at === 'now' ? 'now' : `not before ${at}`
}

// A waiting request can be cancelled; a running one cannot (it ends on its own). The browser's
// confirm() asks first, as in CatherIs Platform (ADR-0028, fifth amendment).
const cancelling = ref<number | null>(null)

function cancelText(r: Schemas['PendingRequest']): string {
  if (r.reason === 'retry' || r.attempt > 1) return 'This retry will not run, and no further retry follows. Run now can start the tool again.'
  if (r.reason === 'schedule') return 'This run will not start. Its schedule still runs at its next time.'
  if (r.reason === 'backfill') return 'This day of history will not be built.'
  return 'This run will not start.'
}

async function cancel(r: Schemas['PendingRequest']): Promise<void> {
  if (!window.confirm(`Cancel ${TOOL_LABEL[r.tool] ?? r.tool} on ${r.connection}? ${cancelText(r)}`)) return
  cancelling.value = r.id
  try {
    await unwrap(api.POST('/api/v1/run-requests/{request_id}/cancel', { params: { path: { request_id: r.id } } }))
    toast(`${TOOL_LABEL[r.tool] ?? r.tool} on ${r.connection} cancelled.`)
  } catch (err) {
    // 404: it started or finished meanwhile; the reload shows where it is now.
    toast(err instanceof ApiError && err.status === 404 ? 'It is no longer waiting: it started or finished meanwhile.' : 'The run was not cancelled.', 'error')
  } finally {
    cancelling.value = null
    await queue.reload()
  }
}

defineExpose({ reload: queue.reload })
</script>

<template>
  <!-- A panel (design-system.md, Card → Panel): a header bar, the table edge to edge. -->
  <section class="card panel" aria-labelledby="q-h">
    <div class="panel-h">
      <div class="titles">
        <h2 id="q-h" class="h2">Queue</h2>
        <span class="cap">Waiting and running. Refreshes every 10 seconds.</span>
      </div>
      <span v-if="queue.data.value" class="cap mono">updated {{ updated }} UTC</span>
    </div>
    <div v-if="backfills.length" class="panel-body backfills">
      <div v-for="b in backfills" :key="b.connection_id" class="backfill">
        <span>Building history for <b>{{ b.connection }}</b></span>
        <span class="mono soft">{{ b.left }} run{{ b.left === 1 ? '' : 's' }} left</span>
      </div>
    </div>
    <div v-if="queue.error.value" class="panel-body"><AlertBanner kind="fail">The queue didn't load: {{ queue.error.value }}</AlertBanner></div>
    <div v-else-if="!queue.data.value" class="panel-body" aria-busy="true"><div class="skeleton sk-120"></div></div>
    <p v-else-if="items.length === 0" class="panel-body cap empty">Nothing queued. Scheduled runs appear here when they are due.</p>
    <div v-else class="table-wrap table-fit">
      <table class="table stackable dense queue-table">
        <thead><tr><th scope="col">Run</th><th scope="col">Reason</th><th scope="col">Status</th><th v-if="props.canCancel" scope="col"><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>
          <tr v-for="r in items" :key="r.id" :class="{ 'row-live': r.status === 'claimed' }">
            <td data-label="Run">
              <ToolChip :tool="r.tool" />
              <span class="sub conn">{{ r.connection }}</span>
            </td>
            <td data-label="Reason" class="reason"><span :class="{ mono: r.reason === 'backfill' }">{{ reason(r) }}</span></td>
            <td data-label="Status">
              <StatusBadge :status="r.status" />
              <span v-if="statusLine(r)" class="sub mono">{{ statusLine(r) }}</span>
            </td>
            <td v-if="props.canCancel" class="actions">
              <button
                v-if="r.status === 'queued'"
                type="button"
                class="btn btn-secondary btn-sm"
                :aria-label="`Cancel ${TOOL_LABEL[r.tool] ?? r.tool} on ${r.connection}`"
                :aria-disabled="cancelling === r.id ? 'true' : undefined"
                @click="cancelling === r.id || cancel(r)"
              >
                <span v-if="cancelling === r.id" class="spinner" aria-hidden="true"></span>✕ Cancel
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-if="total > items.length" class="panel-body cap more">and {{ total - items.length }} more waiting.</p>
    </div>
  </section>
</template>

<style scoped>
.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.backfills {
  display: flex;
  flex-direction: column;
  gap: var(--s-6);
  border-bottom: 1px solid var(--border);
}

.backfill {
  display: flex;
  justify-content: space-between;
  gap: var(--s-8);
  font-size: 13px;
}

.backfill b {
  font-weight: 600;
}

.soft {
  color: var(--text-2);
}

.empty,
.more {
  margin: 0;
}

.actions {
  text-align: right;
}

.queue-table td {
  white-space: nowrap;
}

/* The reason takes what the others leave and may wrap ("Retry 2 of 3 after a failed run"). */
.queue-table td.reason {
  width: 100%;
  white-space: normal;
}

.sub {
  display: block;
  margin-top: 3px;
  font-size: 11px;
  color: var(--text-3);
}

.sub.conn {
  font-size: 12px;
  color: var(--text-2);
}

.row-live > td {
  background: color-mix(in srgb, var(--status-run) 6%, var(--surface));
}

.table tbody tr.row-live:hover > td {
  background: var(--surface-raised);
}
</style>
