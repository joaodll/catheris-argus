<script setup lang="ts">
/** CatherIs Platform's filters card above a list (design-system.md, Filters card). The `after`
 * slot holds a second row under the first, after Clear filters (Findings: More filters). */
import AppIcon from './AppIcon.vue'

defineProps<{ active: boolean; label: string }>()
const emit = defineEmits<{ clear: [] }>()
</script>

<template>
  <section class="card filter-bar" :aria-label="label">
    <slot />
    <button v-if="active" type="button" class="btn btn-ghost btn-sm clear" @click="emit('clear')">
      <AppIcon name="cross" :size="14" :stroke="2.2" />Clear filters
    </button>
    <slot name="after" />
  </section>
</template>

<style scoped>
.filter-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--s-12) var(--s-16);
  padding: var(--s-16);
}

.filter-bar :deep(.select),
.filter-bar :deep(.input) {
  min-width: 160px;
}

.clear {
  gap: var(--s-6);
  margin-left: auto;
  min-height: 40px;
}
</style>
