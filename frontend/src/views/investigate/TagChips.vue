<script setup lang="ts">
/** The Tag filter's chips: one per chosen name, removable (spec frontend/27ceefe0). */
import { computed } from 'vue'
import AppIcon from '@/components/AppIcon.vue'
import { type TagPair, byName, tagWords, withValues } from './tagFilter'

const props = defineProps<{ modelValue: TagPair[] }>()
const emit = defineEmits<{ 'update:modelValue': [TagPair[]] }>()

const CHIP_MAX = 48
const chips = computed(() =>
  byName(props.modelValue).map(({ key, values }) => {
    const full = `Tag: ${tagWords(key, values)}`
    return { key, full, text: full.length > CHIP_MAX ? `${full.slice(0, CHIP_MAX - 1)}…` : full }
  }),
)

function remove(key: string): void {
  emit('update:modelValue', withValues(props.modelValue, key, []))
}
</script>

<template>
  <span v-for="chip in chips" :key="chip.key" class="filter-chip" :title="chip.full">
    <span class="chip-text">{{ chip.text }}</span>
    <button type="button" class="icon-btn chip-x" :aria-label="`Remove tag filter ${chip.key}`" @click="remove(chip.key)">
      <AppIcon name="cross" :size="14" :stroke="2.2" />
    </button>
  </span>
</template>

<style scoped>
.filter-chip {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  height: 32px;
  margin-bottom: var(--s-4);
  padding: 0 var(--s-4) 0 var(--s-10);
  border: 1px solid var(--border-control);
  border-radius: var(--r-control);
  background: var(--surface-raised);
  font-size: 13px;
  max-width: 100%;
}

.chip-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chip-x {
  flex: none;
  width: 24px;
  height: 24px;
}
</style>
