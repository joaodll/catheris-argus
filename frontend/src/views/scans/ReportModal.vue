<script setup lang="ts">
/**
 * New report, or Export from a list (ADR-0047; palace frontend/08ff3c8d). From a list the kind is
 * fixed and the list's filters go along as they are; from Operate -> Reports the person picks the
 * kind and, optionally, the accounts. The worker builds it in the background. Resources is exported
 * from its list only, as a CSV or as JSON Lines with each resource's links and configuration
 * (migrations 0054, 0056; ADR-0047 3c). Misconfigurations and vulnerabilities, by resource (3d), is
 * offered by New report and by the Resources list's Export (its filters choose the resources), or
 * for one resource from its sheet; it adds a severity choice.
 */
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import { useResource } from '@/composables/useResource'
import TagFilter from '@/views/investigate/TagFilter.vue'
import { type TagPair, tagParams } from '@/views/investigate/tagFilter'
import { describe, type ReportFilters } from './reportFilters'

type Kind = 'misconfigurations' | 'vulnerabilities' | 'resources' | 'resource-problems'
type Format = 'csv' | 'pdf' | 'jsonl'
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
const props = defineProps<{
  // Set when exporting from a list: that list's kind and its filters (the API's query shape).
  kind?: Kind
  filters?: ReportFilters
  connections: Schemas['ConnectionOut'][]
  // An account's name where `connections` is not at hand (a resource's sheet).
  accountName?: (id: number) => string
}>()
const emit = defineEmits<{ close: []; requested: [id: number] }>()

const KIND_NAMES: Record<Kind, string> = {
  misconfigurations: 'Misconfigurations',
  vulnerabilities: 'Vulnerabilities',
  resources: 'Resources',
  'resource-problems': 'Misconfigurations and vulnerabilities',
}
const PROBLEMS: { id: Kind; label: string; text: string } = {
  id: 'resource-problems',
  label: 'Misconfigurations and vulnerabilities',
  text: 'Each resource with its failing checks and its CVEs together, worst first.',
}
// New report's kinds; Resources is exported from its list.
const KINDS: { id: Kind; label: string; text: string }[] = [
  { id: 'misconfigurations', label: 'Misconfigurations', text: 'Prowler and CloudFox checks that fail.' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', text: "CVEs from the provider's scanner." },
  PROBLEMS,
]
// The Resources list's Export: the list itself, or its resources' problems.
const RESOURCE_KINDS: { id: Kind; label: string; text: string }[] = [
  { id: 'resources', label: 'Resources', text: 'The list as it is filtered, one resource per row.' },
  PROBLEMS,
]
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
// The formats each kind comes in (the API's KIND_FORMATS), and what each format's choice says.
const FORMATS: Record<Kind, { id: Format; label: string }[]> = {
  misconfigurations: [
    { id: 'csv', label: 'CSV: every row, for a spreadsheet' },
    { id: 'pdf', label: 'PDF: an audit hand-off to send' },
  ],
  vulnerabilities: [
    { id: 'csv', label: 'CSV: every row, for a spreadsheet' },
    { id: 'pdf', label: 'PDF: an audit hand-off to send' },
  ],
  resources: [
    { id: 'csv', label: 'CSV: every row, for a spreadsheet' },
    { id: 'jsonl', label: 'JSON Lines: each resource with its links and configuration' },
  ],
  'resource-problems': [
    { id: 'csv', label: 'CSV: every problem, for a spreadsheet' },
    { id: 'pdf', label: 'PDF: each resource with its problems, to send' },
  ],
}
const FORMAT_NOTES: Record<Kind, string> = {
  misconfigurations: "A PDF gives each check's risk and fix, with at most 25 resources per check and 5,000 in all. The CSV has every row.",
  vulnerabilities: "A PDF gives each CVE's risk and fix, with at most 25 resources per CVE and 5,000 in all. The CSV has every row.",
  'resource-problems':
    'A PDF gives each resource its open misconfigurations and CVEs, worst resource first, with at most 40 problems per resource, 300 resources in full and 5,000 problems in all; each check or CVE is explained once at the end. The CSV has every problem.',
  resources:
    'JSON Lines holds one resource per line: the CSV\'s columns, its links, and its configuration as Argus stores it (secrets masked), plus the resources it links to in these accounts. Compressed (.jsonl.gz), for jq, scripts or a SIEM rather than a spreadsheet.',
}
const fromList = props.kind !== undefined
// From the Resources list, the person picks the list or its resources' problems.
const fromResources = props.kind === 'resources'
const kind = ref<Kind>(props.kind ?? 'misconfigurations')
// The by-resource kind's severities; none chosen is every severity.
const severities = ref<Severity[]>([])
const format = ref<Format>('csv')
const formats = computed(() => FORMATS[kind.value])
// A kind that doesn't come in the chosen format starts again from a CSV.
watch(kind, (k) => {
  if (!FORMATS[k].some((f) => f.id === format.value)) format.value = 'csv'
})
// From a list, its filters; "Clear filters" drops them (the report then covers all open).
const listFilters = ref<ReportFilters | null>(props.filters ?? null)
const allAccounts = ref(true)
const chosen = ref<number[]>([])
const sending = ref(false)
const error = ref<string | null>(null)

// What this install keeps: asked when the modal opens, so the lists need no extra request.
const reports = useResource(() => unwrap(api.GET('/api/v1/reports', { params: { query: { limit: 1 } } })))
const storage = computed(() => reports.data.value?.storage ?? null)
const local = computed(() => storage.value === 'local')
// Why no report can be requested now, or null when one can (the API's own sentences).
const unavailable = computed((): string | null => {
  switch (storage.value) {
    case 'off':
      return 'This install keeps no reports. On Kubernetes they need IRSA roles for the API and the report Job.'
    case 'no_identity':
      return "Reports can't be stored now: the API has no IRSA identity. See the install notes."
    case 'no_bucket':
      return 'Reports go to the raw-output bucket, and none is set. An Admin sets it in Settings, Raw output storage.'
    default:
      return null
  }
})
// On a local store only Demo connections can be reported on; on S3, every connection.
const offered = computed(() => props.connections.filter((c) => !local.value || c.kind === 'demo'))

const title = computed(() => (fromResources ? 'Export' : fromList ? `Export ${KIND_NAMES[kind.value]}` : 'New report'))
// New report's tags (spec frontend/27ceefe0): the names the kind's list offers over the accounts.
const tags = ref<TagPair[]>([])
const scopeIds = computed(() => (allAccounts.value ? offered.value.map((c) => c.id) : chosen.value))
const scopeKey = computed(() => scopeIds.value.join(','))
const tagNames = useResource(
  async () => {
    if (fromList) return null
    const query = { connection_id: scopeIds.value }
    const facets =
      kind.value !== 'vulnerabilities'
        ? await unwrap(api.GET('/api/v1/findings/facets', { params: { query } }))
        : await unwrap(api.GET('/api/v1/vulnerabilities/facets', { params: { query } }))
    return facets.tags
  },
  { watch: [kind, scopeKey] },
)
const tagStatus = computed(() => (tagNames.error.value ? 'error' : tagNames.data.value ? 'ready' : 'loading'))

const everything = computed(() => (kind.value === 'resources' ? 'All resources' : 'All open'))
const filterWords = computed(() =>
  listFilters.value
    ? describe(listFilters.value, (id) => props.connections.find((c) => c.id === id)?.name ?? props.accountName?.(id) ?? `#${id}`, everything.value)
    : '',
)
const dirty = computed(
  () =>
    format.value !== 'csv' ||
    severities.value.length > 0 ||
    (fromResources && kind.value !== 'resources') ||
    (!fromList && (kind.value !== 'misconfigurations' || !allAccounts.value || tags.value.length > 0)),
)
const canSend = computed(
  () =>
    !sending.value &&
    (storage.value === 'local' || storage.value === 's3') &&
    (fromList || allAccounts.value || chosen.value.length > 0),
)

function filtersToSend(): ReportFilters {
  const severity = kind.value === 'resource-problems' && severities.value.length ? { severity: severities.value } : {}
  if (listFilters.value) return { ...listFilters.value, ...severity }
  if (fromList) return severity
  const tag = tags.value.length ? { tag: tagParams(tags.value) } : {}
  if (allAccounts.value) return offered.value.length ? { connection_id: offered.value.map((c) => c.id), ...tag, ...severity } : { ...tag, ...severity }
  return { connection_id: chosen.value, ...tag, ...severity }
}

async function send(): Promise<void> {
  if (!canSend.value) return
  sending.value = true
  error.value = null
  try {
    const body = { kind: kind.value, format: format.value, filters: filtersToSend() } as
      | Schemas['MisconfigurationReportIn']
      | Schemas['VulnerabilityReportIn']
      | Schemas['ResourcesReportIn']
      | Schemas['ResourceProblemsReportIn']
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
    <AlertBanner v-else-if="unavailable" :kind="storage === 'off' ? undefined : 'warn'">{{ unavailable }}</AlertBanner>
    <form v-else id="report-form" class="form" @submit.prevent="send">
      <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
      <fieldset v-if="!fromList" class="choices">
        <legend class="lbl">Report</legend>
        <label v-for="k in KINDS" :key="k.id" class="check kind">
          <input v-model="kind" type="radio" name="report-kind" :value="k.id">
          <span><span class="kind-name">{{ k.label }}</span><span class="cap">{{ k.text }}</span></span>
        </label>
      </fieldset>
      <fieldset v-if="fromResources" class="choices">
        <legend class="lbl">Report</legend>
        <label v-for="k in RESOURCE_KINDS" :key="k.id" class="check kind">
          <input v-model="kind" type="radio" name="report-kind" :value="k.id">
          <span><span class="kind-name">{{ k.label }}</span><span class="cap">{{ k.text }}</span></span>
        </label>
      </fieldset>
      <fieldset class="choices">
        <legend class="lbl">Format</legend>
        <label v-for="f in formats" :key="f.id" class="check"><input v-model="format" type="radio" name="report-format" :value="f.id">{{ f.label }}</label>
        <span class="cap">{{ FORMAT_NOTES[kind] }}</span>
      </fieldset>
      <fieldset v-if="kind === 'resource-problems'" class="choices">
        <legend class="lbl">Severity</legend>
        <div class="severities">
          <label v-for="s in SEVERITIES" :key="s" class="check"><input v-model="severities" type="checkbox" :value="s">{{ s.charAt(0).toUpperCase() + s.slice(1) }}</label>
        </div>
        <span class="cap">{{ severities.length ? 'Only problems of these severities.' : 'Every severity.' }}</span>
      </fieldset>
      <div v-if="fromList" class="field">
        <span class="lbl">Filters from the list</span>
        <span class="filters">{{ listFilters ? filterWords : `${everything}, every account` }}</span>
        <button v-if="listFilters" type="button" class="btn btn-ghost btn-sm clear" @click="listFilters = null">Clear filters</button>
      </div>
      <fieldset v-else class="choices">
        <legend class="lbl">Accounts</legend>
        <label class="check"><input v-model="allAccounts" type="radio" name="report-scope" :value="true">{{ local ? 'All Demo accounts' : 'All accounts' }}</label>
        <label class="check"><input v-model="allAccounts" type="radio" name="report-scope" :value="false">Only these accounts</label>
        <div v-if="!allAccounts" class="accounts">
          <label v-for="c in offered" :key="c.id" class="check"><input v-model="chosen" type="checkbox" :value="c.id">{{ c.name }}</label>
          <span v-if="chosen.length === 0" class="cap">Choose at least one account.</span>
        </div>
        <span class="cap">All open findings of these accounts. To narrow a report by anything else, export it from its list.</span>
      </fieldset>
      <TagFilter
        v-if="!fromList"
        id="report-tag"
        :list="kind === 'vulnerabilities' ? 'vulnerabilities' : 'misconfigurations'"
        :names="tagNames.data.value"
        :status="tagStatus"
        :connection-ids="scopeIds"
        :model-value="tags"
        chips
        @update:model-value="tags = $event"
      />
      <p v-if="local" class="cap">Reports on this install cover Demo connections only.</p>
    </form>
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">{{ unavailable ? 'Close' : 'Cancel' }}</button>
      <button v-if="!unavailable" type="submit" form="report-form" class="btn btn-primary" :disabled="!canSend">
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

.severities {
  display: flex;
  flex-wrap: wrap;
  gap: 0 var(--s-16);
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
