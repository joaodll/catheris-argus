<script setup lang="ts">
/**
 * A sortable column header: the <th> carries aria-sort, its button says what a click does
 * (design-system.md, Table).
 */
import { computed } from 'vue'

const props = defineProps<{
  label: string
  direction: 'desc' | 'asc' | null
  descText: string // "newest first"
  ascText: string // "oldest first"
}>()
const emit = defineEmits<{ toggle: [] }>()

const sort = computed(() => (props.direction === 'desc' ? 'descending' : props.direction === 'asc' ? 'ascending' : 'none'))
const name = computed(() => {
  if (props.direction === null) return `${props.label}, not sorted. Sort ${props.descText}`
  const now = props.direction === 'desc' ? props.descText : props.ascText
  const next = props.direction === 'desc' ? props.ascText : props.descText
  return `${props.label}, sorted ${now}. Sort ${next}`
})
</script>

<template>
  <th scope="col" :aria-sort="sort">
    <button type="button" class="sort" :class="{ 'is-sorted': direction }" :aria-label="name" @click="emit('toggle')">
      {{ label }}<span class="arrow" aria-hidden="true">{{ direction === 'desc' ? '▼' : direction === 'asc' ? '▲' : '▲▼' }}</span>
    </button>
  </th>
</template>

<style scoped>
.sort {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  padding: 0;
  border: 0;
  background: none;
  color: inherit;
  font: inherit;
  letter-spacing: inherit;
  text-transform: inherit;
  cursor: pointer;
}

.arrow {
  font-size: 9px;
  color: var(--text-3);
}

.sort.is-sorted,
.sort.is-sorted .arrow {
  color: var(--text);
}
</style>
