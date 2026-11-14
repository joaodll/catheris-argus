<script setup lang="ts">
/**
 * One row of the Resource map's start: a link, with a type's glyph when `showDisc` is set, a name, an
 * optional second line and an optional count on the right.
 */
import type { RouteLocationRaw } from 'vue-router'
import AppIcon from '@/components/AppIcon.vue'
import { resourceGlyph } from '../resourceGlyph'

defineProps<{
  to: RouteLocationRaw
  name: string
  label: string
  title?: string
  type?: string | null
  showDisc?: boolean
  meta?: string
  mono?: boolean
  monoMeta?: boolean
  count?: number
}>()
</script>

<template>
  <RouterLink class="open" :to="to" :title="title" :aria-label="label">
    <span v-if="showDisc" class="disc" aria-hidden="true">
      <AppIcon :name="resourceGlyph(type ?? null)" :size="16" :stroke="1.6" />
    </span>
    <span class="text">
      <span class="name" :class="{ mono }">{{ name }}</span>
      <span v-if="meta" class="meta" :class="{ mono: monoMeta }">{{ meta }}</span>
    </span>
    <span v-if="count != null" class="mono count">{{ count.toLocaleString('en-US') }}</span>
  </RouterLink>
</template>

<style scoped>
.open {
  display: flex;
  flex: 1 1 auto;
  align-items: center;
  gap: var(--s-12);
  min-width: 0;
  min-height: 44px;
  padding: var(--s-6) var(--s-8);
  border-radius: var(--r-control);
  color: inherit;
  text-decoration: none;
}

.open:hover {
  background: var(--surface-active);
}

.open:focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
}

.disc {
  display: inline-flex;
  flex: 0 0 32px;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  border: 1px solid var(--border-strong);
  background: var(--surface-sunken);
  color: var(--text-2);
}

.text {
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  min-width: 0;
}

.name {
  overflow: hidden;
  color: var(--text);
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.meta {
  overflow: hidden;
  color: var(--text-2);
  font-size: 12.5px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.count {
  flex: 0 0 auto;
  color: var(--text-2);
}
</style>
