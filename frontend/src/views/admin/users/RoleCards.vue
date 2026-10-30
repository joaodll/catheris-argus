<script setup lang="ts">
/** The three roles as radio cards, one line each (docs/ui/screens.md, E13; ADR-0041). */
import type { Role } from '@/composables/useSession'

const props = defineProps<{ modelValue: Role; disabled?: boolean; name: string }>()
const emit = defineEmits<{ 'update:modelValue': [role: Role] }>()

const ROLES: { value: Role; title: string; text: string }[] = [
  { value: 'viewer', title: 'Viewer', text: 'Reads every screen except Users and Settings.' },
  { value: 'operator', title: 'Operator', text: 'Also adds and edits connections, runs and schedules scans.' },
  { value: 'admin', title: 'Admin', text: 'Also changes Settings and manages users.' },
]
</script>

<template>
  <fieldset class="roles">
    <legend class="lbl">Role</legend>
    <label
      v-for="r in ROLES"
      :key="r.value"
      class="radio-card"
      :class="{ 'is-selected': props.modelValue === r.value, 'is-disabled': props.disabled }"
    >
      <input
        type="radio"
        :name="props.name"
        :value="r.value"
        :checked="props.modelValue === r.value"
        :disabled="props.disabled"
        @change="emit('update:modelValue', r.value)"
      >
      <span class="rc-text"><b>{{ r.title }}</b><span class="cap">{{ r.text }}</span></span>
    </label>
  </fieldset>
</template>

<style scoped>
.roles {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  margin: 0;
  padding: 0;
  border: 0;
}

.rc-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
</style>
