<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import MultiSelect, { type MultiOption } from '@/components/MultiSelect.vue'
import { useDirtyGuard } from '@/composables/useDirtyGuard'
import { useResource } from '@/composables/useResource'
import { toast } from '@/composables/useToasts'
import NumberField from './NumberField.vue'
import SettingsCard from './SettingsCard.vue'

const props = defineProps<{ collection: Schemas['CollectionSettings'] }>()
const emit = defineEmits<{ saved: [collection: Schemas['CollectionSettings']] }>()

interface Form {
  parallel: number
  window: number
  cooldown: number
  retry1: number
  retry2: number
  minInterval: number
  goroutines: number
  steampipeParallel: number
  throttlePercent: number
  regions: string
  prowlerRetries: number
  skipServices: string[]
  skipChecks: string[]
}

/** "eu-west-1, us-east-1" or one per line -> ["eu-west-1", "us-east-1"]. */
function regionList(text: string): string[] {
  return text.split(/[\s,]+/).filter(Boolean)
}

function fromSettings(s: Schemas['CollectionSettings']): Form {
  return {
    parallel: s.max_parallel_runs,
    window: s.stagger_window_minutes,
    cooldown: s.run_now_cooldown_minutes,
    retry1: s.retry_delays_minutes?.[0] ?? 30,
    retry2: s.retry_delays_minutes?.[1] ?? 120,
    minInterval: s.schedule_min_interval_minutes,
    goroutines: s.cloudfox_max_goroutines,
    steampipeParallel: s.steampipe_parallel_tables,
    throttlePercent: Math.round(s.synthetic_throttle_share * 1000) / 10,
    regions: (s.aws_regions ?? []).join(', '),
    prowlerRetries: s.prowler_retry_attempts ?? 10,
    skipServices: [...(s.prowler_skip_services ?? [])],
    skipChecks: [...(s.prowler_skip_checks ?? [])],
  }
}

// What the pinned Prowler can skip: its services, and its checks (a check's service is the
// first word of its id, shown before it so the list reads by service).
const prowler = useResource(() => unwrap(api.GET('/api/v1/settings/collection/prowler-options')))
const prowlerStatus = computed(() => (prowler.error.value ? 'error' : prowler.data.value ? 'ready' : 'loading'))
const serviceOptions = computed<MultiOption[]>(() => (prowler.data.value?.services ?? []).map((s) => ({ value: s, label: s, mono: true })))
const checkOptions = computed<MultiOption[]>(() => (prowler.data.value?.checks ?? []).map((c) => ({ value: c, label: c, mono: true })))
// A skip stored before a Prowler upgrade removed its name can't be shown in the picker, and the
// API refuses a save that holds it: such names are left out of the save (the worker already
// ignores them). Without the lists, the values go as they are.
function known(values: string[], names: string[] | undefined): string[] {
  if (!names) return values
  const current = new Set(names)
  return values.filter((v) => current.has(v))
}
const skipping = computed(() => form.value.skipServices.length + form.value.skipChecks.length > 0)

const saved = ref<Form>(fromSettings(props.collection))
const form = ref<Form>({ ...saved.value })
// Only when this topic's values change (its own save, or a reload).
watch(() => JSON.stringify(props.collection), () => {
  saved.value = fromSettings(props.collection)
  form.value = { ...saved.value }
})
const dirty = computed(() => JSON.stringify(form.value) !== JSON.stringify(saved.value))
useDirtyGuard(dirty)

const saving = ref(false)
const error = ref<string | null>(null)

async function save(): Promise<void> {
  saving.value = true
  error.value = null
  const f = form.value
  try {
    const result = await unwrap(
      api.PUT('/api/v1/settings/collection', {
        body: {
          max_parallel_runs: f.parallel,
          stagger_window_minutes: f.window,
          run_now_cooldown_minutes: f.cooldown,
          retry_delays_minutes: [f.retry1, f.retry2],
          schedule_min_interval_minutes: f.minInterval,
          cloudfox_max_goroutines: f.goroutines,
          steampipe_parallel_tables: f.steampipeParallel,
          synthetic_throttle_share: f.throttlePercent / 100,
          aws_regions: regionList(f.regions),
          prowler_retry_attempts: f.prowlerRetries,
          prowler_skip_services: known(f.skipServices, prowler.data.value?.services),
          prowler_skip_checks: known(f.skipChecks, prowler.data.value?.checks),
        },
      }),
    )
    emit('saved', result)
    toast('Collection settings saved. The change is in the audit log.')
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The settings were not saved.'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <SettingsCard
    id="collection"
    title="Collection and throttling"
    description="How hard Argus may push each account's APIs. Takes effect on the next run, no restart."
    :dirty="dirty"
    :saving="saving"
    :error="error"
    save-label="Save collection settings"
    @save="save"
    @discard="form = { ...saved }"
  >
    <div class="form-grid">
      <NumberField v-model="form.parallel" label="Max parallel runs" :min="1" help="Runs on different accounts at the same time. One account never runs two at once." />
      <NumberField v-model="form.window" label="Start window" unit="minutes" :min="0" help="Scheduled accounts start at their own offset within this window." />
      <NumberField v-model="form.cooldown" label="Run now cooldown" unit="minutes" :min="0" help="A tool that ran on an account this recently is skipped by Run now." />
      <div class="field">
        <span id="retry-l" class="lbl">Retry delays</span>
        <div class="pair" role="group" aria-labelledby="retry-l">
          <NumberField v-model="form.retry1" label="First retry" unit="min" :min="1" help="" />
          <NumberField v-model="form.retry2" label="Second retry" unit="min" :min="1" help="" />
        </div>
        <span class="cap">A failed run is retried after {{ form.retry1 }}, then {{ form.retry2 }} minutes, then waits for its schedule. A partial run is not retried.</span>
      </div>
      <NumberField v-model="form.minInterval" label="Minimum schedule interval" unit="minutes" :min="15" help="Schedules that run more often are refused. At least 15 minutes." />
      <NumberField v-model="form.goroutines" label="CloudFox concurrency" :min="1" help="Parallel API calls per CloudFox run. Upstream default is 30; lower is gentler." />
      <NumberField v-model="form.steampipeParallel" label="Steampipe tables at once" :min="1" :max="8" help="Tables exported at the same time in one Steampipe run (about 400 tables). Higher is faster; lower is gentler on API limits." />
      <NumberField v-model="form.throttlePercent" label="Synthetic throttling share" unit="%" :min="0" :max="100" :step="0.1" help="Demo connections only: the share of runs that simulate throttling." />
      <div class="field">
        <label class="lbl" for="aws-regions">AWS regions to scan</label>
        <input id="aws-regions" v-model="form.regions" class="input mono" autocomplete="off" spellcheck="false" placeholder="All enabled regions" aria-describedby="aws-regions-help">
        <span id="aws-regions-help" class="cap">Prowler, Steampipe and the vulnerability scanner read only these, comma-separated. Empty scans every enabled region. CloudFox always scans every region. What a removed region held stays as last scanned, with its last-seen date, until it is scanned again.</span>
      </div>
      <fieldset class="group">
        <legend class="lbl">Prowler</legend>
        <MultiSelect id="prowler-skip-services" v-model="form.skipServices" label="Services to skip" :options="serviceOptions" :status="prowlerStatus" empty-label="None" />
        <MultiSelect id="prowler-skip-checks" v-model="form.skipChecks" label="Checks to skip" :options="checkOptions" :status="prowlerStatus" empty-label="None" />
        <NumberField v-model="form.prowlerRetries" label="Retry attempts per AWS call" :min="1" :max="20" help="How often Prowler tries a throttled call before it gives up on it. Higher is more patient; the run takes longer when AWS throttles." />
        <p class="cap note" :class="{ on: skipping }">
          A skipped service or check keeps its last results until it runs again: nothing is resolved because it was skipped.
          While anything is skipped, compliance stays complete, but Prowler's 43 checks that belong to no framework don't run either.
        </p>
      </fieldset>
    </div>
  </SettingsCard>
</template>

<style scoped>
/* The Prowler settings: a group of their own, across the whole grid. */
.group {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px var(--s-20); /* as .form-grid, which it continues */
  margin: 0;
  padding: var(--s-12) 0 0;
  border: 0;
  border-top: 1px solid var(--border);
}

@media (max-width: 700px) {
  .group {
    grid-template-columns: minmax(0, 1fr);
  }
}

/* A skip list is a form field here, not a filter: as wide as the other inputs. */
.group :deep(.ms-trigger) {
  width: 100%;
  max-width: none;
}

.group > legend {
  padding: 0 0 var(--s-8);
}

.group .note {
  grid-column: 1 / -1;
  margin: 0;
}

.group .note.on {
  color: var(--status-warn);
}

.pair {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--s-8);
}

.pair :deep(.lbl) {
  font-size: 10px;
}

.pair :deep(.cap:empty) {
  display: none;
}
</style>
