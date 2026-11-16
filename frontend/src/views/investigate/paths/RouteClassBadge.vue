<script setup lang="ts">
/**
 * How sure Argus is of a route (spec W6 §1.1): an icon and a word, in --text-2 on a tile, the
 * shape of a chip. No severity or status colour: confidence is not severity. The meaning is the
 * title and, for screen readers, hidden text.
 */
import AppIcon from '@/components/AppIcon.vue'
import { CLASS_ICON, CLASS_LABEL, CLASS_MEANING, type RouteClass } from './routeClass'

defineProps<{ cls: RouteClass }>()
</script>

<template>
  <span class="route-class" :title="CLASS_MEANING[cls]">
    <AppIcon :name="CLASS_ICON[cls]" :size="13" :stroke="2.2" />
    <span>{{ CLASS_LABEL[cls] }}</span>
    <span class="sr-only">: {{ CLASS_MEANING[cls] }}</span>
  </span>
</template>

<style scoped>
.route-class {
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
  height: 22px;
  padding: 0 var(--s-8);
  border: 1px solid var(--border);
  border-radius: var(--r-pill);
  background: var(--tile);
  color: var(--text-2);
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
}

.route-class :deep(svg) {
  flex: none;
}
</style>
