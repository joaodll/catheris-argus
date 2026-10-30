<script setup lang="ts">
/**
 * A cron expression with the API's plain-language preview (design-system.md, Cron field).
 * The preview is the API's own check, so what it accepts is exactly what saving accepts.
 */
import { onScopeDispose, ref, useId, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ modelValue: string; minInterval: number | null }>()
const emit = defineEmits<{ 'update:modelValue': [value: string]; valid: [ok: boolean] }>()

const PRESETS = [
  { label: 'Daily 02:00', cron: '0 2 * * *' },
  { label: 'Every 6 hours', cron: '0 */6 * * *' },
  { label: 'Weekly, Sunday 03:00', cron: '0 3 * * 0' },
]

const id = useId()
const preview = ref<Schemas['CronOut'] | null>(null)
const error = ref<string | null>(null)
const checking = ref(false)
let timer = 0
let generation = 0

async function check(cron: string): Promise<void> {
  const mine = ++generation
  checking.value = true
  try {
    const result = await unwrap(api.POST('/api/v1/schedules/preview', { body: { cron } }))
    if (mine !== generation) return
    preview.value = result
    error.value = null
    emit('valid', true)
  } catch (err) {
    if (mine !== generation) return
    error.value = err instanceof ApiError ? err.message : 'This expression could not be checked.'
    emit('valid', false)
  } finally {
    if (mine === generation) checking.value = false
  }
}

watch(
  () => props.modelValue,
  (cron) => {
    window.clearTimeout(timer)
    if (cron.trim().split(/\s+/).length < 5) {
      error.value = 'A cron expression has five fields: minute, hour, day of month, month, day of week.'
      emit('valid', false)
      return
    }
    timer = window.setTimeout(() => void check(cron.trim()), 400)
  },
  { immediate: true },
)
onScopeDispose(() => window.clearTimeout(timer))
</script>

<template>
  <div class="field">
    <label class="lbl" :for="id">When (cron, UTC)</label>
    <div class="presets">
      <button
        v-for="p in PRESETS"
        :key="p.cron"
        type="button"
        class="btn btn-secondary btn-sm"
        @click="emit('update:modelValue', p.cron)"
      >
        {{ p.label }}
      </button>
    </div>
    <input
      :id="id"
      class="input mono"
      :value="props.modelValue"
      spellcheck="false"
      autocomplete="off"
      :aria-invalid="error ? 'true' : undefined"
      :aria-describedby="`${id}-preview ${id}-help`"
      @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    >
    <span v-if="error" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ error }}</span>
    <div :id="`${id}-preview`" class="preview" aria-live="polite">
      <AppIcon v-if="checking" name="spinner" :size="12" :stroke="2.6" class="checking" />
      <template v-if="preview">
        <span class="explain" :class="{ stale: error }">{{ preview.explanation }}</span>
        <template v-if="!error">
          <span class="lbl">Next runs (UTC)</span>
          <span v-for="run in preview.next_runs" :key="run" class="mono next">{{ run.slice(0, 16).replace('T', ' ') }}</span>
        </template>
      </template>
      <span v-else-if="!error" class="cap">Checking…</span>
    </div>
    <span :id="`${id}-help`" class="cap">
      Minimum interval: {{ props.minInterval == null ? 'set in Settings' : `${props.minInterval} minutes` }}.
    </span>
  </div>
</template>

<style scoped>
.presets {
  display: flex;
  gap: var(--s-6);
  flex-wrap: wrap;
}

.preview {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding: var(--s-12);
  background: var(--surface-sunken);
  border: 1px solid var(--border);
  border-radius: var(--r-control);
  min-height: 46px;
}

.checking {
  position: absolute;
  top: 10px;
  right: 10px;
  color: var(--text-3);
}

.explain {
  font-size: 14px;
}

.explain.stale {
  color: var(--text-3);
  text-decoration: line-through;
}

.next {
  font-size: 12px;
  color: var(--text-2);
}
</style>
