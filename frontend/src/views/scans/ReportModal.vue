<script setup lang="ts">
/**
 * New report, or Export from a list (ADR-0047; palace frontend/08ff3c8d). From a list the kind is
 * fixed and the list's filters go along as they are; from Operate -> Reports the person picks the
 * kind and, optionally, the accounts. The worker builds it in the background.
 */
import { computed, ref } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import { useResource } from '@/composables/useResource'
import { describe, type ReportFilters } from './reportFilters'

type Kind = 'misconfigurations' | 'vulnerabilities'
const props = defineProps<{
  // Set when exporting from a list: that list's kind and its filters (the API's query shape).
  kind?: Kind
  filters?: ReportFilters
  connections: Schemas['ConnectionOut'][]
}>()
const emit = defineEmits<{ close: []; requested: [id: number] }>()

const KINDS: { id: Kind; label: string; text: string }[] = [
  { id: 'misconfigurations', label: 'Misconfigurations', text: 'Prowler and CloudFox checks that fail.' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', text: "CVEs from the provider's scanner." },
]
const fromList = props.kind !== undefined
const kind = ref<Kind>(props.kind ?? 'misconfigurations')
const format = ref<'csv' | 'pdf'>('csv')
// From a list, its filters; "Clear filters" drops them (the report then covers all open).
const listFilters = ref<ReportFilters | null>(props.filters ?? null)
const allAccounts = ref(true)
const chosen = ref<number[]>([])
const sending = ref(false)
const error = ref<string | null>(null)

// What this install keeps: asked when the modal opens, so the lists need no extra request.
const reports = useResource(() => unwrap(api.GET('/api/v1/reports', { params: { query: { limit: 1 } } })))
const storage = computed(() => reports.data.value?.storage ?? null)
// On a local store only Demo connections can be reported on.
const offered = computed(() => props.connections.filter((c) => storage.value !== 'local' || c.kind === 'demo'))

const title = computed(() =>
  fromList ? `Export ${kind.value === 'misconfigurations' ? 'Misconfigurations' : 'Vulnerabilities'}` : 'New report',
)
const filterWords = computed(() =>
  listFilters.value ? describe(listFilters.value, (id) => props.connections.find((c) => c.id === id)?.name ?? `#${id}`) : '',
)
const dirty = computed(
  () => format.value !== 'csv' || (!fromList && (kind.value !== 'misconfigurations' || !allAccounts.value)),
)
const canSend = computed(
  () => !sending.value && storage.value === 'local' && (fromList || allAccounts.value || chosen.value.length > 0),
)

function filtersToSend(): ReportFilters {
  if (listFilters.value) return listFilters.value
  if (allAccounts.value) return offered.value.length ? { connection_id: offered.value.map((c) => c.id) } : {}
  return { connection_id: chosen.value }
}

async function send(): Promise<void> {
  if (!canSend.value) return
  sending.value = true
  error.value = null
  try {
    const body = { kind: kind.value, format: format.value, filters: filtersToSend() } as Schemas['MisconfigurationReportIn']
    const queued = await unwrap(api.POST('/api/v1/reports', { body }))
    emit('requested', queued.id)
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The report was not requested.'
  } finally {
    sending.value = false
  }
}
</script>

<template>
  <AppModal :title="title" description="Built in the background. You can leave this page." :dirty="dirty" @close="emit('close')">
    <div v-if="reports.error.value">
      <AlertBanner kind="fail">Reports didn't load: {{ reports.error.value }}</AlertBanner>
    </div>
    <div v-else-if="!reports.data.value" aria-busy="true" class="skeleton sk-48"></div>
    <AlertBanner v-else-if="storage === 'off'">
      Reports are not available on this install yet. They need the reports folder of the raw-output bucket, which comes in a later release.
    </AlertBanner>
    <form v-else id="report-form" class="form" @submit.prevent="send">
      <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
      <fieldset v-if="!fromList" class="choices">
        <legend class="lbl">Report</legend>
        <label v-for="k in KINDS" :key="k.id" class="check kind">
          <input v-model="kind" type="radio" name="report-kind" :value="k.id">
          <span><span class="kind-name">{{ k.label }}</span><span class="cap">{{ k.text }}</span></span>
        </label>
      </fieldset>
      <fieldset class="choices">
        <legend class="lbl">Format</legend>
        <label class="check"><input v-model="format" type="radio" name="report-format" value="csv">CSV: every row, for a spreadsheet</label>
        <label class="check"><input v-model="format" type="radio" name="report-format" value="pdf">PDF: an audit hand-off to send</label>
        <span class="cap">A PDF gives each check's risk and fix, with at most 25 resources per check and 5,000 in all. The CSV has every row.</span>
      </fieldset>
      <div v-if="fromList" class="field">
        <span class="lbl">Filters from the list</span>
        <span class="filters">{{ listFilters ? filterWords : 'All open, every account' }}</span>
        <button v-if="listFilters" type="button" class="btn btn-ghost btn-sm clear" @click="listFilters = null">Clear filters</button>
      </div>
      <fieldset v-else class="choices">
        <legend class="lbl">Accounts</legend>
        <label class="check"><input v-model="allAccounts" type="radio" name="report-scope" :value="true">All Demo accounts</label>
        <label class="check"><input v-model="allAccounts" type="radio" name="report-scope" :value="false">Only these accounts</label>
        <div v-if="!allAccounts" class="accounts">
          <label v-for="c in offered" :key="c.id" class="check"><input v-model="chosen" type="checkbox" :value="c.id">{{ c.name }}</label>
          <span v-if="chosen.length === 0" class="cap">Choose at least one account.</span>
        </div>
        <span class="cap">All open findings of these accounts. To narrow a report, export it from its list.</span>
      </fieldset>
      <p v-if="storage === 'local'" class="cap">Reports on this install cover Demo connections only.</p>
    </form>
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">{{ storage === 'off' ? 'Close' : 'Cancel' }}</button>
      <button v-if="storage !== 'off'" type="submit" form="report-form" class="btn btn-primary" :disabled="!canSend">
        <AppIcon v-if="sending" name="spinner" :size="16" :stroke="2.4" />{{ sending ? 'Requesting…' : 'Request report' }}
      </button>
    </template>
  </AppModal>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.choices {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.kind > span {
  display: flex;
  flex-direction: column;
}

.kind-name {
  font-weight: 600;
}

.accounts {
  display: flex;
  flex-direction: column;
  padding-left: 28px;
}

.filters {
  font-size: 14px;
  overflow-wrap: anywhere;
}

.clear {
  align-self: flex-start;
  padding: 0;
}
</style>
