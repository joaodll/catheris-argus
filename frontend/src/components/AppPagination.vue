<script setup lang="ts">
/**
 * CatherIs Platform's pagination (‹ page / pages ›, the record count on the right), in Argus's
 * tokens (design-system.md, Table). Pages count from 1.
 */
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'

const props = withDefaults(
  // `capped`: a search counted only up to `total`, and there are more ("10,000+ records").
  defineProps<{ total: number; page: number; limit?: number; noun?: string; capped?: boolean }>(),
  { limit: 20, noun: 'record', capped: false },
)
const emit = defineEmits<{ change: [page: number] }>()

const pages = computed(() => Math.max(1, Math.ceil(props.total / props.limit)))
const count = computed(
  () => `${props.total.toLocaleString('en-US')}${props.capped ? '+' : ''} ${props.noun}${props.total === 1 && !props.capped ? '' : 's'}`,
)
</script>

<template>
  <nav class="pagination" aria-label="Pagination">
    <template v-if="pages > 1">
      <button type="button" class="btn btn-secondary page-btn" aria-label="Previous page" :disabled="page <= 1" @click="emit('change', page - 1)">
        <AppIcon name="chevron" :size="16" :stroke="2.2" class="prev" />
      </button>
      <span class="mono position" aria-live="polite">{{ page }} / {{ pages }}</span>
      <button type="button" class="btn btn-secondary page-btn" aria-label="Next page" :disabled="page >= pages" @click="emit('change', page + 1)">
        <AppIcon name="chevron" :size="16" :stroke="2.2" />
      </button>
    </template>
    <span class="cap total">{{ count }}</span>
  </nav>
</template>

<style scoped>
.pagination {
  display: flex;
  align-items: center;
  gap: var(--s-8);
  padding-top: var(--s-12);
}

.page-btn {
  width: 32px;
  height: 32px;
  padding: 0;
  justify-content: center;
}

.prev {
  transform: rotate(180deg);
}

.position {
  min-width: 56px;
  text-align: center;
  font-size: 13px;
  color: var(--text);
}

.total {
  margin-left: auto;
}
</style>
