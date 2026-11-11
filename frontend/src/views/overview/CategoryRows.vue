<script setup lang="ts">
/**
 * Assets by category (assetTypes.ts), one row each: name, bar, count and share. A row opens in
 * place to its largest types, each a link to Resources filtered by that type: Resources filters
 * on types, and a category can hold more than its 50-value limit, so there is no category link.
 * Shared by the Overview's Inventory card and the Resources Summary (round 5, frontend/1d636dd5).
 */
import { computed, ref } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import AppIcon from '@/components/AppIcon.vue'
import { int, percent } from '@/format'
import { OTHER, type TypeGroup } from './assetTypes'

const props = defineProps<{
  id: string
  label: string
  groups: TypeGroup[]
  counts: Map<string, number>
  /** The largest count on the bar scale (the Overview shares one scale across providers). */
  max: number
  total: number
  typeLink: (type: string) => RouteLocationRaw
  moreLink: RouteLocationRaw
  /** The link text for where the types not shown are: "Resources", "the list". */
  moreWhere: string
}>()

const TYPES_SHOWN = 10
const opened = ref<Set<string>>(new Set())
function toggle(name: string): void {
  const next = new Set(opened.value)
  if (next.has(name)) next.delete(name)
  else next.add(name)
  opened.value = next
}

const rows = computed(() =>
  props.groups.map((g) => {
    const share = props.total ? (g.count / props.total) * 100 : null
    return {
      ...g,
      share,
      width: `max(2px, ${(g.count / Math.max(1, props.max)) * 100}%)`,
      key: `${props.id}-${g.name.toLowerCase()}`,
      text: `${g.name}: ${int(g.count)} assets, ${percent(share)}`,
      top: g.types
        .map((type) => ({ type, count: props.counts.get(type) ?? 0 }))
        .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type))
        .slice(0, TYPES_SHOWN),
      more: Math.max(0, g.types.length - TYPES_SHOWN),
    }
  }),
)
</script>

<template>
  <ul class="rows" :aria-label="label">
    <li v-for="r in rows" :key="r.name">
      <button type="button" class="row" :aria-expanded="opened.has(r.name)" :aria-controls="r.key" @click="toggle(r.name)">
        <span class="sr-only">{{ r.text }}</span>
        <span class="name" aria-hidden="true"><AppIcon name="chevron" :size="14" :stroke="2" class="chev" />{{ r.name }}</span>
        <span class="track mark-track" aria-hidden="true">
          <span class="fill mark-bar" :class="{ 'no-glow': r.name === OTHER }" :style="{ width: r.width, '--series': r.color }"></span>
        </span>
        <b class="mono count" aria-hidden="true">{{ int(r.count) }}</b>
        <span class="mono share" aria-hidden="true">{{ percent(r.share) }}</span>
      </button>
      <ul v-if="opened.has(r.name)" :id="r.key" class="types" :aria-label="`${r.name}: largest types`">
        <li v-for="t in r.top" :key="t.type" class="type">
          <RouterLink class="row-link mono tname" :to="typeLink(t.type)" :aria-label="`${t.type}: ${int(t.count)} assets, show in Resources`">{{ t.type }}</RouterLink>
          <span class="mono tcount">{{ int(t.count) }}</span>
        </li>
        <li v-if="r.more" class="cap">
          and {{ r.more }} more type{{ r.more === 1 ? '' : 's' }} in <RouterLink :to="moreLink">{{ moreWhere }}</RouterLink>
        </li>
      </ul>
    </li>
  </ul>
</template>

<style scoped>
.rows {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
}

.row {
  width: 100%;
  padding: 0;
  border: 0;
  border-radius: var(--r-control);
  background: none;
  color: inherit;
  text-align: left;
  cursor: pointer;
  display: grid;
  grid-template-columns: 104px minmax(0, 1fr) 64px 48px;
  grid-template-areas: 'name bar count share';
  gap: var(--s-12);
  align-items: center;
  min-height: 32px;
  font-size: 13px;
}

.row:hover .name {
  color: var(--link);
}

.name {
  grid-area: name;
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
}

.chev {
  flex: none;
  color: var(--text-3);
  transition: transform var(--ease);
}

.row[aria-expanded='true'] .chev {
  transform: rotate(90deg);
}

.types {
  list-style: none;
  margin: 0 0 var(--s-8);
  padding: var(--s-4) 0 var(--s-4) 22px;
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.type {
  display: flex;
  justify-content: space-between;
  gap: var(--s-12);
  min-height: 24px;
  align-items: center;
}

.tname {
  min-width: 0;
  overflow: hidden;
  font-size: 12px;
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tcount {
  font-size: 12px;
  color: var(--text-2);
}

.track {
  grid-area: bar;
  display: block;
  height: 12px;
  border-radius: 4px;
}

.fill {
  display: block;
  height: 100%;
  border-radius: 4px;
}

.count {
  grid-area: count;
  font-weight: 600;
  text-align: right;
}

.share {
  grid-area: share;
  font-size: 12px;
  color: var(--text-3);
  text-align: right;
}

@media (max-width: 600px) {
  .row {
    grid-template-columns: minmax(0, 1fr) auto 48px;
    grid-template-areas:
      'name count share'
      'bar bar bar';
    gap: var(--s-4) var(--s-12);
    padding-bottom: var(--s-6);
  }
}
</style>
