<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import { useDirtyGuard } from '@/composables/useDirtyGuard'
import { toast } from '@/composables/useToasts'
import NumberField from './NumberField.vue'
import SettingsCard from './SettingsCard.vue'

const props = defineProps<{ settings: Schemas['SettingsOut'] }>()
const emit = defineEmits<{ saved: [settings: Schemas['SettingsOut']] }>()

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
  }
}

const saved = ref<Form>(fromSettings(props.settings.collection))
const form = ref<Form>({ ...saved.value })
// Only when this topic's values change (its own save, or a reload): saving another card
// replaces the settings object but must not discard edits here.
watch(() => JSON.stringify(props.settings.collection), () => {
  saved.value = fromSettings(props.settings.collection)
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
        <span id="aws-regions-help" class="cap">Prowler and Steampipe scan only these, comma-separated. Empty scans every enabled region. CloudFox always scans every region.</span>
      </div>
    </div>
  </SettingsCard>
</template>

<style scoped>
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
