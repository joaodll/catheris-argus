<script setup lang="ts">
import { useId } from 'vue'
import AppIcon from '@/components/AppIcon.vue'

const props = defineProps<{ label: string; modelValue: number; unit?: string; help: string; min?: number; max?: number; step?: number; error?: string | null }>()
const emit = defineEmits<{ 'update:modelValue': [value: number] }>()
const id = useId()
</script>

<template>
  <div class="field">
    <label class="lbl" :for="id">{{ props.label }}</label>
    <span class="unit-wrap">
      <input
        :id="id"
        class="input mono"
        type="number"
        :min="props.min"
        :max="props.max"
        :step="props.step ?? 1"
        :value="props.modelValue"
        :aria-invalid="props.error ? 'true' : undefined"
        :aria-describedby="`${id}-help`"
        :style="props.unit ? { paddingRight: '72px' } : undefined"
        @input="emit('update:modelValue', Number(($event.target as HTMLInputElement).value))"
      >
      <span v-if="props.unit" class="unit mono" aria-hidden="true">{{ props.unit }}</span>
    </span>
    <span v-if="props.error" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ props.error }}</span>
    <span :id="`${id}-help`" class="cap">{{ props.help }}</span>
  </div>
</template>

<style scoped>
.unit-wrap {
  position: relative;
  display: block;
}

.unit {
  position: absolute;
  right: var(--s-12);
  top: 50%;
  transform: translateY(-50%);
  font-size: 12px;
  color: var(--text-3);
  pointer-events: none;
}
</style>
