<script setup lang="ts">
/**
 * A framework's requirements on its latest day (screens.md E10, item 5), grouped by section,
 * filtered by status and a search, 50 per page. For all connections a requirement fails when
 * any account fails it, and the table shows how many do.
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import type { Status } from './compliance'

const props = defineProps<{
  requirements: Schemas['RequirementList'] | null
  error: string | null
  allConnections: boolean
  scope: string
  status: Status | null
  q: string
  page: number
  limit: number
}>()
const emit = defineEmits<{ status: [status: Status | null]; search: [q: string]; page: [page: number]; retry: [] }>()

const STATUS_CHOICES: { value: Status | null; label: string }[] = [
  { value: null, label: 'All' },
  { value: 'FAIL', label: 'Fail' },
  { value: 'MANUAL', label: 'Manual' },
  { value: 'PASS', label: 'Pass' },
]
const STATUS_VIEW: Record<Status, { label: string; icon: 'check' | 'cross' | 'half'; cls: string; title?: string }> = {
  PASS: { label: 'Pass', icon: 'check', cls: 'ok' },
  FAIL: { label: 'Fail', icon: 'cross', cls: 'fail' },
  MANUAL: { label: 'Manual', icon: 'half', cls: 'manual', title: 'Needs a person to check: not scored' },
}

const search = ref(props.q)
let typing: number | undefined
watch(search, (value) => {
  window.clearTimeout(typing)
  typing = window.setTimeout(() => {
    if (value.trim() !== props.q) emit('search', value.trim())
  }, 300)
})
watch(
  () => props.q,
  (q) => {
    if (q !== search.value.trim()) search.value = q
  },
)
onBeforeUnmount(() => window.clearTimeout(typing))

type Row = Schemas['RequirementOut']
/** Rows with a section heading before the first of each section on the page. */
const groups = computed(() => {
  const items = props.requirements?.items ?? []
  const out: { section: string; continued: boolean; fails: number; rows: Row[] }[] = []
  items.forEach((r, i) => {
    const section = r.section ?? 'No section'
    let group = out[out.length - 1]
    if (!group || group.section !== section) {
      group = { section, continued: i === 0 && props.page > 1, fails: 0, rows: [] }
      out.push(group)
    }
    group.rows.push(r)
    if (r.status === 'FAIL') group.fails += 1
  })
  return out
})
const columns = computed(() => (props.allConnections ? 5 : 4) + 1)
const open = ref(new Set<string>())
function toggle(id: string): void {
  const next = new Set(open.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  open.value = next
}
const filtered = computed(() => Boolean(props.status || props.q))
</script>

<template>
  <section class="card stack" aria-labelledby="req-h">
    <div class="head">
      <div class="titles">
        <h2 id="req-h" class="h2">Requirements</h2>
        <span class="cap">
          <template v-if="props.requirements?.data_through">As of <span class="mono">{{ props.requirements.data_through }}</span> · </template>{{ props.scope }}
        </span>
      </div>
      <div class="controls">
        <div class="segmented" role="group" aria-label="Status">
          <button v-for="c in STATUS_CHOICES" :key="c.label" type="button" :aria-pressed="props.status === c.value" @click="emit('status', c.value)">{{ c.label }}</button>
        </div>
        <span class="search-wrap">
          <label class="sr-only" for="req-q">Search requirements</label>
          <AppIcon name="search" :size="16" class="search-icon" />
          <input id="req-q" v-model="search" class="input" type="search" placeholder="Search requirements" maxlength="200" autocomplete="off">
        </span>
      </div>
    </div>

    <AlertBanner v-if="props.error" kind="fail">
      Requirements didn't load: {{ props.error }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="emit('retry')">Retry</button></template>
    </AlertBanner>
    <div v-else-if="!props.requirements" aria-busy="true" class="loading"><div v-for="n in 5" :key="n" class="skeleton sk-48"></div></div>
    <EmptyState v-else-if="props.requirements.items.length === 0 && filtered" icon="info" title="No requirements match.">
      <button type="button" class="btn btn-secondary" @click="search = ''; emit('status', null); emit('search', '')">Show all</button>
    </EmptyState>
    <EmptyState v-else-if="props.requirements.items.length === 0" icon="checklist" :title="`No requirements recorded for ${props.scope}.`" />
    <div v-else class="table-wrap">
      <table class="table stackable reqs">
        <thead>
          <tr>
            <th scope="col">Id</th>
            <th scope="col">Requirement</th>
            <th scope="col">Status</th>
            <th scope="col">Checks</th>
            <th v-if="props.allConnections" scope="col" class="right">Accounts failing</th>
            <th scope="col"><span class="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody v-for="g in groups" :key="g.section">
          <tr class="section">
            <th scope="colgroup" :colspan="columns">
              <span class="eyebrow">{{ g.section }}{{ g.continued ? ' (continued)' : '' }}</span>
              <span v-if="g.fails" class="fail mono">{{ g.fails }} fail</span>
            </th>
          </tr>
          <template v-for="r in g.rows" :key="r.requirement_id">
            <tr>
              <td data-label="Id" class="mono id">{{ r.requirement_id }}</td>
              <td data-label="Requirement" class="req"><span class="clamp">{{ r.title || r.description }}</span></td>
              <td data-label="Status">
                <span class="status" :class="STATUS_VIEW[r.status].cls" :title="STATUS_VIEW[r.status].title">
                  <AppIcon :name="STATUS_VIEW[r.status].icon" :size="14" />{{ STATUS_VIEW[r.status].label }}
                </span>
              </td>
              <td data-label="Checks" class="mono checks">
                <template v-if="r.passed_checks || r.failed_checks">{{ r.passed_checks }} passed · {{ r.failed_checks }} failed</template>
                <span v-else class="soft">No checks</span>
              </td>
              <td v-if="props.allConnections" data-label="Accounts failing" class="right mono" :class="{ fail: (r.fail_connections ?? 0) > 0 }">
                {{ r.fail_connections ?? 0 }} of {{ r.assessed_connections ?? 0 }}
              </td>
              <td data-label="">
                <button
                  type="button"
                  class="icon-btn chev"
                  :aria-expanded="open.has(r.requirement_id)"
                  :aria-label="`${open.has(r.requirement_id) ? 'Hide' : 'Show'} the description of ${r.requirement_id}`"
                  @click="toggle(r.requirement_id)"
                >
                  <AppIcon name="chevron" :size="16" :stroke="2" />
                </button>
              </td>
            </tr>
            <tr v-if="open.has(r.requirement_id)" class="detail">
              <td :colspan="columns"><p class="description">{{ r.description }}</p></td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
    <AppPagination
      v-if="props.requirements?.items.length"
      :total="props.requirements.total"
      :page="props.page"
      :limit="props.limit"
      noun="requirement"
      @change="emit('page', $event)"
    />
  </section>
</template>

<style scoped>
.head {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: var(--s-12);
  flex-wrap: wrap;
}

.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.controls {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-12);
  align-items: center;
}

.search-wrap {
  position: relative;
  display: block;
  min-width: 220px;
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

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.section th {
  padding-top: var(--s-14);
  text-align: left;
  background: transparent;
}

.section .eyebrow {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-3);
}

.section .fail {
  margin-left: var(--s-12);
  font-size: 11px;
}

.id {
  font-size: 12px;
  white-space: nowrap;
}

.req {
  max-width: 560px;
}

.clamp {
  display: -webkit-box;
  overflow: hidden;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  font-size: 13px;
  font-weight: 500;
}

.status {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  font-weight: 500;
  white-space: nowrap;
}

.ok {
  color: var(--status-ok);
}

.fail {
  color: var(--status-fail);
}

.manual {
  color: var(--text-2);
}

.checks {
  font-size: 12px;
  white-space: nowrap;
}

.soft {
  color: var(--text-3);
}

.chev :deep(svg) {
  transition: transform var(--ease);
}

.chev[aria-expanded='true'] :deep(svg) {
  transform: rotate(90deg);
}

.table tr.detail > td {
  background: var(--tile);
}

.description {
  max-width: 880px;
  margin: 0;
  font-size: 13px;
  line-height: 1.5;
  color: var(--text-2);
  white-space: pre-line;
}
</style>
