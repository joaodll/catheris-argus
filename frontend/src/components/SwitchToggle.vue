<script setup lang="ts">
/** A switch with its state in words. While `busy`, it is disabled and shows a spinner. */
import AppIcon from './AppIcon.vue'

const props = defineProps<{ modelValue: boolean; busy?: boolean; label?: string; disabled?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>

<template>
  <button
    type="button"
    role="switch"
    class="switch"
    :aria-checked="props.modelValue"
    :aria-label="props.label"
    :disabled="props.busy || props.disabled"
    @click="emit('update:modelValue', !props.modelValue)"
  >
    <span class="track" :class="{ on: props.modelValue }">
      <AppIcon v-if="props.busy" name="spinner" :size="10" :stroke="3" class="knob-spin" />
    </span>
    <span>{{ props.modelValue ? 'Enabled' : 'Disabled' }}</span>
  </button>
</template>

<style scoped>
.switch {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
  min-height: 32px;
  padding: 0;
  border: 0;
  background: none;
  color: var(--text);
  font-size: 13px;
  cursor: pointer;
}

.switch:disabled {
  cursor: progress;
}

.track {
  position: relative;
  width: 36px;
  height: 20px;
  flex-shrink: 0;
  border-radius: 999px;
  border: 1px solid var(--border-control);
  background: var(--surface-sunken);
  transition: background var(--ease), border-color var(--ease);
}

.track::after {
  content: '';
  position: absolute;
  top: 3px;
  left: 3px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--text-3);
  transition: left var(--ease);
}

.track.on {
  background: var(--accent);
  border-color: var(--accent);
}

.track.on::after {
  left: 19px;
  background: var(--on-accent);
}

.knob-spin {
  position: absolute;
  top: 4px;
  left: 12px;
  color: var(--text);
  z-index: 1;
}

.track.on .knob-spin {
  color: var(--on-accent);
}

.switch:disabled .track::after {
  opacity: 0;
}
</style>
