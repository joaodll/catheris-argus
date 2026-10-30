<script setup lang="ts">
/** The range buttons of a history chart (design-system.md; the Overview's severity trend). */
import { RANGES, type Range } from './chart'

const props = defineProps<{ range: Range }>()
const emit = defineEmits<{ select: [range: Range] }>()
</script>

<template>
  <div role="group" aria-label="Time range" class="ranges">
    <button
      v-for="r in RANGES"
      :key="r.id"
      type="button"
      class="mono range"
      :aria-pressed="r.id === props.range"
      :aria-label="r.label"
      @click="emit('select', r.id)"
    >
      {{ r.id }}
    </button>
  </div>
</template>

<style scoped>
.ranges {
  display: flex;
  gap: 2px;
  padding: 3px;
  background: var(--tile);
  border: 1px solid var(--border-strong);
  border-radius: var(--r-control);
}

.range {
  height: 32px;
  min-width: 44px;
  padding: 0 var(--s-12);
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text-2);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
}

.range[aria-pressed='true'] {
  background: var(--border);
  color: var(--text);
  box-shadow: inset 0 -2px 0 var(--accent);
}
</style>
