<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import { useDirtyGuard } from '@/composables/useDirtyGuard'
import { toast } from '@/composables/useToasts'
import NumberField from './NumberField.vue'
import SettingsCard from './SettingsCard.vue'

const props = defineProps<{ settings: Schemas['SettingsOut'] }>()
const emit = defineEmits<{ saved: [settings: Schemas['SettingsOut']] }>()

const saved = ref({ ...props.settings.retention })
const form = ref({ ...saved.value })
// Only when this topic's values change: another card's save must not discard edits here.
watch(() => JSON.stringify(props.settings.retention), () => {
  saved.value = { ...props.settings.retention }
  form.value = { ...saved.value }
})
const dirty = computed(() => JSON.stringify(form.value) !== JSON.stringify(saved.value))
useDirtyGuard(dirty)
const max = computed(() => props.settings.bounds.max_history_days)

const saving = ref(false)
const error = ref<string | null>(null)
const fieldError = ref<string | null>(null)

async function save(): Promise<void> {
  saving.value = true
  error.value = fieldError.value = null
  try {
    const result = await unwrap(api.PUT('/api/v1/settings/retention', { body: form.value }))
    emit('saved', result)
    toast('Retention saved. The change is in the audit log.')
  } catch (err) {
    const message = err instanceof ApiError ? err.message : 'Retention was not saved.'
    if (message.includes('history_days')) fieldError.value = message
    else error.value = message
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <SettingsCard
    id="retention"
    title="Retention"
    description="How long daily history is kept. Older monthly partitions are dropped nightly."
    :dirty="dirty"
    :saving="saving"
    :error="error"
    save-label="Save retention"
    @save="save"
    @discard="form = { ...saved }; fieldError = null"
  >
    <div class="form-grid">
      <NumberField
        v-model="form.history_days"
        label="History"
        unit="days"
        :min="1"
        :max="max"
        :error="fieldError"
        :help="`Up to ${max} days, the limit set by the operator.`"
      />
      <NumberField v-model="form.demo_raw_days" label="Demo raw files" unit="days" :min="1" help="Raw demo files are regenerable, so they are kept briefly." />
    </div>
  </SettingsCard>
</template>
