<script setup lang="ts">
/**
 * A password the user types, with a Show toggle: sign-in, choosing a new password and changing
 * your own (docs/ui/screens.md, E1 and E13). The label belongs to the caller (`for` = `id`).
 */
import { ref } from 'vue'
import AppIcon from './AppIcon.vue'

const props = defineProps<{
  id: string
  modelValue: string
  autocomplete: 'current-password' | 'new-password'
  readonly?: boolean
  invalid?: boolean
  describedby?: string
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const shown = ref(false)
const input = ref<HTMLInputElement | null>(null)

defineExpose({ focus: () => input.value?.focus() })
</script>

<template>
  <div class="wrap">
    <input
      :id="props.id"
      ref="input"
      class="input"
      :type="shown ? 'text' : 'password'"
      :autocomplete="props.autocomplete"
      :value="props.modelValue"
      :readonly="props.readonly"
      :aria-invalid="props.invalid ? 'true' : undefined"
      :aria-describedby="props.describedby"
      spellcheck="false"
      required
      @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    >
    <button type="button" class="icon-btn reveal" :aria-label="shown ? 'Hide password' : 'Show password'" :aria-pressed="shown" @click="shown = !shown">
      <AppIcon :name="shown ? 'eye-off' : 'eye'" :size="16" />
    </button>
  </div>
</template>

<style scoped>
.wrap {
  position: relative;
}

.wrap .input {
  width: 100%;
  padding-right: 44px;
}

.reveal {
  position: absolute;
  right: 3px;
  top: 50%;
  transform: translateY(-50%);
}
</style>
