<script setup lang="ts">
/**
 * A write-only credential (design-system.md, Secret field). A stored secret is never shown:
 * only that it is set, and when. The input is never prefilled, and its value leaves this
 * component only through v-model, as the user types it.
 */
import { ref, useId } from 'vue'
import AppIcon from './AppIcon.vue'

const props = defineProps<{
  label: string
  modelValue: string
  setOn?: string | null
  help?: string
  error?: string | null
  allowGenerate?: boolean
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const id = useId()
const shown = ref(false)
const replacing = ref(false)

function generate(): void {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  emit('update:modelValue', Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''))
  shown.value = true
}

function stopReplacing(): void {
  replacing.value = false
  emit('update:modelValue', '')
}
</script>

<template>
  <div class="field">
    <label class="lbl" :for="id">{{ props.label }}</label>
    <div v-if="props.setOn && !replacing" class="set-line">
      <span class="badge-set"><AppIcon name="check" :size="12" :stroke="2.6" />Set</span>
      <span v-if="/^\d{4}-\d{2}-\d{2}/.test(props.setOn)">on <span class="mono">{{ props.setOn.slice(0, 10) }}</span></span>
      <button :id="id" type="button" class="btn btn-secondary btn-sm" @click="replacing = true">Replace</button>
    </div>
    <template v-else>
      <div class="row">
        <div class="wrap">
          <input
            :id="id"
            class="input mono"
            :type="shown ? 'text' : 'password'"
            autocomplete="new-password"
            spellcheck="false"
            :value="props.modelValue"
            :aria-invalid="props.error ? 'true' : undefined"
            :aria-describedby="`${id}-help`"
            @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
          >
          <button
            type="button"
            class="icon-btn reveal"
            :aria-label="shown ? 'Hide value' : 'Show value'"
            :aria-pressed="shown"
            @click="shown = !shown"
          >
            <AppIcon :name="shown ? 'eye-off' : 'eye'" :size="18" />
          </button>
        </div>
        <button v-if="props.allowGenerate" type="button" class="btn btn-secondary" @click="generate">Generate</button>
        <button v-if="replacing" type="button" class="btn btn-secondary" @click="stopReplacing">Cancel</button>
      </div>
      <span v-if="props.error" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ props.error }}</span>
    </template>
    <span :id="`${id}-help`" class="cap">
      {{ replacing ? 'The current secret stays in use until you save.' : props.help ?? 'Stored encrypted. Never shown again after you save.' }}
    </span>
  </div>
</template>

<style scoped>
.set-line {
  display: flex;
  align-items: center;
  gap: var(--s-10);
  flex-wrap: wrap;
  font-size: 13px;
}

.badge-set {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 22px;
  padding: 0 8px;
  border-radius: var(--r-chip);
  background: color-mix(in srgb, var(--status-ok) 12%, transparent);
  color: var(--status-ok);
  font-size: 11px;
  font-weight: 600;
}

.row {
  display: flex;
  gap: var(--s-8);
}

.wrap {
  position: relative;
  flex: 1;
  min-width: 0;
}

.wrap .input {
  padding-right: 44px;
}

.reveal {
  position: absolute;
  right: 4px;
  top: calc((var(--control-h) - 32px) / 2);
}
</style>
