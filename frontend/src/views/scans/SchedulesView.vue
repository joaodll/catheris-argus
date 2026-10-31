<script setup lang="ts">
import type { Collector } from '@/tools'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import FilterBar from '@/components/FilterBar.vue'
import LiveIndicator from '@/components/LiveIndicator.vue'
import PageHeader from '@/components/PageHeader.vue'
import RefreshButton from '@/components/RefreshButton.vue'
import SwitchToggle from '@/components/SwitchToggle.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { can } from '@/composables/useSession'
import { toast } from '@/composables/useToasts'
import QueueCard from './QueueCard.vue'
import RunNowCard from './RunNowCard.vue'
import ScheduleModal from './ScheduleModal.vue'

const PAGE = 20
const search = ref('') // what is typed
const query = ref('') // what is searched, 300 ms after typing stops
const page = ref(1)
let typing: number | undefined
watch(search, (value) => {
  window.clearTimeout(typing)
  typing = window.setTimeout(() => {
    query.value = value.trim()
    page.value = 1
  }, 300)
})

const schedules = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/schedules', {
        params: { query: { q: query.value || null, limit: PAGE, offset: (page.value - 1) * PAGE } },
      }),
    ),
  { watch: [query, page] },
)
const items = computed(() => schedules.data.value?.items ?? [])
const total = computed(() => schedules.data.value?.total ?? 0)
// A page that no longer exists (after a deletion) moves to the last one.
watch(total, (count) => {
  const last = Math.max(1, Math.ceil(count / PAGE))
  if (page.value > last) page.value = last
})

onBeforeUnmount(() => window.clearTimeout(typing))

function clearSearch(): void {
  window.clearTimeout(typing)
  search.value = ''
  query.value = ''
  page.value = 1
}
const connections = useResource(() => unwrap(api.GET('/api/v1/connections')))
const settings = useResource(() => unwrap(api.GET('/api/v1/settings')))
// Each tool's last run per connection: Run now and a new schedule tick Vulnerabilities only where it ran.
const context = useResource(() => unwrap(api.GET('/api/v1/context', { params: { query: { connection_id: 0 } } })))
const lastRuns = computed(() => context.data.value?.last_runs ?? null)

const editing = ref<Schemas['ScheduleOut'] | 'new' | null>(null)
const deleting = ref<number | null>(null)
const toggling = ref<Set<number>>(new Set())
const queue = ref<InstanceType<typeof QueueCard> | null>(null)
// A Viewer reads schedules and the queue; an Operator or Admin changes them (ADR-0041).
const operator = computed(() => can('operator'))
const admin = computed(() => can('admin'))
const runningCount = ref(0)

function scopeOf(s: Schemas['ScheduleOut']): { text: string; title: string } {
  if (s.all_connections) return { text: 'All connections', title: '' }
  const names = s.connection_ids.map((id) => connections.data.value?.find((c) => c.id === id)?.name ?? `#${id}`)
  const shown = names.slice(0, 2).join(', ')
  return { text: names.length > 2 ? `${shown} +${names.length - 2}` : shown, title: names.join(', ') }
}

async function setEnabled(s: Schemas['ScheduleOut'], enabled: boolean): Promise<void> {
  toggling.value = new Set(toggling.value).add(s.id)
  try {
    await unwrap(
      api.PUT('/api/v1/schedules/{schedule_id}', {
        params: { path: { schedule_id: s.id } },
        body: {
          name: s.name,
          tools: s.tools as Collector[],
          cron: s.cron,
          connection_ids: s.all_connections ? null : s.connection_ids,
          enabled,
        },
      }),
    )
    // Disabling cancels the runs it had queued: the queue shows it at once.
    await Promise.all([schedules.reload(), queue.value?.reload()])
    toast(`${s.name} ${enabled ? 'enabled' : 'disabled'}.`)
  } catch (err) {
    toast(err instanceof ApiError ? err.message : 'The change was not saved.', 'error')
  } finally {
    const next = new Set(toggling.value)
    next.delete(s.id)
    toggling.value = next
  }
}

// Deleting asks with the browser's confirm(), as in CatherIs Platform (ADR-0028, fifth amendment).
async function remove(s: Schemas['ScheduleOut']): Promise<void> {
  if (!window.confirm(`Delete the schedule “${s.name}”? Its queued runs are cancelled. History is kept.`)) return
  deleting.value = s.id
  try {
    await unwrap(api.DELETE('/api/v1/schedules/{schedule_id}', { params: { path: { schedule_id: s.id } } }))
    await Promise.all([schedules.reload(), queue.value?.reload()])
    toast(`${s.name} deleted.`)
  } catch (err) {
    toast(err instanceof ApiError ? err.message : 'The schedule was not deleted.', 'error')
  } finally {
    deleting.value = null
  }
}

// The schedules and the queue, on demand.
function refresh(): Promise<unknown> {
  return Promise.all([schedules.reload(), queue.value?.reload()])
}

async function onSaved(message: string): Promise<void> {
  editing.value = null
  await Promise.all([schedules.reload(), queue.value?.reload()])
  toast(message)
}
</script>

<template>
  <PageHeader title="Schedules">
    Times are UTC.
    <template #actions><LiveIndicator :count="runningCount" /><RefreshButton :reload="refresh" /></template>
  </PageHeader>
  <FilterBar label="Search schedules" :active="search !== ''" @clear="clearSearch">
    <div class="field search">
      <label class="lbl" for="sch-q">Search</label>
      <span class="search-wrap">
        <AppIcon name="search" :size="16" class="search-icon" />
        <input id="sch-q" v-model="search" class="input" type="search" placeholder="Search schedules by name" maxlength="100" autocomplete="off">
      </span>
    </div>
  </FilterBar>

  <!-- The Platform's list panel: a header bar, the table edge to edge, a footer bar. -->
  <section class="card panel" aria-labelledby="sch-h">
    <div class="panel-h">
      <div class="titles">
        <h2 id="sch-h" class="h2">Schedules</h2>
        <span class="cap">When each tool runs, and on which connections.</span>
      </div>
      <button v-if="operator" type="button" class="btn btn-primary" @click="editing = 'new'"><AppIcon name="plus" :size="16" :stroke="2.2" />New schedule</button>
    </div>

    <div v-if="schedules.error.value" class="panel-body">
      <AlertBanner kind="fail">
        Schedules didn't load: {{ schedules.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="schedules.reload">Retry</button></template>
      </AlertBanner>
    </div>
    <div v-else-if="!schedules.data.value" aria-busy="true" class="panel-body loading"><div v-for="n in 3" :key="n" class="skeleton sk-48"></div></div>
    <div v-else-if="items.length === 0 && query" class="panel-body">
      <EmptyState icon="info" :title="`No schedules match &quot;${query}&quot;.`">
        <button type="button" class="btn btn-secondary" @click="clearSearch">Clear filters</button>
      </EmptyState>
    </div>
    <div v-else-if="items.length === 0" class="panel-body">
      <EmptyState icon="clock" title="No schedules yet." text="Tools run only when you start them, until a schedule exists.">
        <button v-if="operator" type="button" class="btn btn-secondary" @click="editing = 'new'">New schedule</button>
      </EmptyState>
    </div>
    <div v-else class="table-wrap table-fit">
      <table class="table stackable stack-narrow dense schedules-table">
        <thead>
          <tr><th scope="col">Name</th><th scope="col">When</th><th scope="col">Scope</th><th scope="col">Enabled</th><th v-if="operator" scope="col"><span class="sr-only">Actions</span></th></tr>
        </thead>
        <tbody>
          <tr v-for="s in items" :key="s.id" :class="{ 'is-off': !s.enabled }">
            <td data-label="Name" class="name">
              <button v-if="operator" type="button" class="row-link" @click="editing = s">{{ s.name }}</button>
              <span v-else class="plain-name">{{ s.name }}</span>
              <span class="tools"><ToolChip v-for="t in s.tools" :key="t" :tool="t" /></span>
            </td>
            <td data-label="When">
              <span class="when">
                <span class="explain">{{ s.explanation }}</span>
                <span class="mono cron">{{ s.cron }}</span>
                <span class="mono next">Next {{ s.enabled && s.next_runs[0] ? `${s.next_runs[0].slice(0, 16).replace('T', ' ')} UTC` : '—' }}</span>
              </span>
            </td>
            <td data-label="Scope"><span :title="scopeOf(s).title">{{ scopeOf(s).text }}</span></td>
            <td data-label="Enabled">
              <span v-if="!operator">{{ s.enabled ? 'Enabled' : 'Disabled' }}</span>
              <SwitchToggle v-else :model-value="s.enabled" :busy="toggling.has(s.id)" :label="`Schedule ${s.name}`" @update:model-value="(v) => setEnabled(s, v)" />
            </td>
            <td v-if="operator" data-label="">
              <button type="button" class="btn btn-danger btn-sm" :aria-label="`Delete ${s.name}`" :aria-disabled="deleting === s.id ? 'true' : undefined" @click="deleting === s.id || remove(s)"><span v-if="deleting === s.id" class="spinner" aria-hidden="true"></span>Delete</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="items.length" class="panel-foot">
      <AppPagination :total="total" :page="page" :limit="PAGE" @change="(p) => (page = p)" />
    </div>
    <div v-if="settings.data.value" class="panel-body settings-note">
      <AlertBanner>
        Each account starts at its own offset within {{ settings.data.value.collection.stagger_window_minutes }} minutes, one run per account at a time,
        at most {{ settings.data.value.collection.max_parallel_runs }} runs in parallel.
        <template v-if="admin"><RouterLink :to="{ name: 'settings' }">Change these in Settings</RouterLink>.</template>
      </AlertBanner>
    </div>
  </section>

  <div :class="{ two: operator }">
    <RunNowCard
      v-if="operator"
      :connections="connections.data.value"
      :last-runs="lastRuns"
      :cooldown="settings.data.value?.collection.run_now_cooldown_minutes ?? null"
      @queued="queue?.reload()"
    />
    <QueueCard ref="queue" :can-cancel="operator" @running="runningCount = $event" />
  </div>

  <ScheduleModal
    v-if="editing"
    :schedule="editing === 'new' ? null : editing"
    :connections="connections.data.value ?? []"
    :last-runs="lastRuns"
    :min-interval="settings.data.value?.collection.schedule_min_interval_minutes ?? null"
    @close="editing = null"
    @saved="onSaved"
  />
</template>

<style scoped>
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

.tools {
  display: flex;
  gap: var(--s-6);
  flex-wrap: wrap;
  margin-top: var(--s-4);
}

.schedules-table td {
  white-space: nowrap;
}

/* The name column takes what the others leave. */
.schedules-table td.name {
  width: 100%;
  white-space: normal;
}

/* After the footer bar, the settings note sits apart from the table. */
.settings-note {
  border-top: 1px solid var(--border);
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

.when {
  display: flex;
  flex-direction: column;
}

.explain {
  font-size: 14px;
}

.cron {
  font-size: 12px;
  color: var(--text-3);
}

.next {
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
}

/* A Viewer's schedule name: the row link's look, without the link. */
.plain-name {
  font-size: 14px;
  font-weight: 600;
}

.two {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: var(--s-16);
  align-items: start;
}

@media (max-width: 1150px) {
  .two {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
