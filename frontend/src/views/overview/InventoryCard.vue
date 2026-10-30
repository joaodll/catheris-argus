<script setup lang="ts">
/**
 * Steampipe inventory: assets by type, per provider (docs/ui/screens.md, "Inventory: assets by
 * type, per provider"). One bar scale across providers, so a bigger estate shows longer bars.
 */
import { computed, ref } from 'vue'
import type { Schemas } from '@/api/client'
import AppIcon from '@/components/AppIcon.vue'
import ToolChip from '@/components/ToolChip.vue'
import { int, longDate, percent } from '@/format'
import { byProvider } from './assetTypes'
import { resources } from './drill'

const props = defineProps<{ data: Schemas['Overview'] | null; connectionId: number }>()

// A group opens in place to its largest types, each a link to Resources: Resources filters on
// one type, and a group (classified here, assetTypes.ts) can hold dozens of them.
const TYPES_SHOWN = 10
const opened = ref<Set<string>>(new Set())
function toggle(key: string): void {
  const next = new Set(opened.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  opened.value = next
}
const countOf = computed(() => new Map((props.data?.inventory.by_type ?? []).map((t) => [t.type, t.count])))

const providers = computed(() => {
  const list = byProvider(props.data?.inventory.by_type ?? [], props.data?.coverage ?? {})
  const max = Math.max(1, ...list.flatMap((p) => p.groups.map((g) => g.count)))
  return list.map((p) => ({
    ...p,
    rows: p.groups.map((g) => {
      const share = p.total ? (g.count / p.total) * 100 : null
      return {
        ...g,
        share,
        width: `max(2px, ${(g.count / max) * 100}%)`,
        key: `${p.id}-${g.name}`,
        text: `${g.name}: ${int(g.count)} assets, ${percent(share)}`,
        top: [...g.types]
          .map((type) => ({ type, count: countOf.value.get(type) ?? 0 }))
          .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type))
          .slice(0, TYPES_SHOWN),
        more: Math.max(0, g.types.length - TYPES_SHOWN),
      }
    }),
  }))
})
</script>

<template>
  <section class="card stack" aria-labelledby="inv-h">
    <div class="card-head">
      <div class="titles">
        <div class="title-row"><ToolChip tool="steampipe" /><h2 id="inv-h" class="h2">Inventory</h2></div>
        <span class="sub">{{ int(data?.kpis.assets.value) }} assets · as of {{ data?.data_through ? longDate(data.data_through) : '…' }}</span>
      </div>
    </div>
    <span class="lbl">Assets by type, per provider</span>
    <template v-if="data">
      <div v-for="p in providers" :key="p.id" class="provider">
        <div class="prov-head">
          <span class="pname"><span class="dot" :class="p.covered ? ['mark-dot', `dot-${p.id}`] : ['nc-dot', `dot-${p.id}`]"></span>{{ p.name }}</span>
          <span v-if="!p.covered" class="nc">not covered</span>
          <span v-else class="total"><b class="mono">{{ p.total == null ? '—' : int(p.total) }}</b> assets</span>
        </div>
        <ul v-if="p.rows.length" class="rows" :aria-label="`${p.name} assets by type`">
          <li v-for="r in p.rows" :key="r.name">
            <button type="button" class="row" :aria-expanded="opened.has(r.key)" :aria-controls="`inv-${r.key}`" @click="toggle(r.key)">
              <span class="sr-only">{{ r.text }}</span>
              <span class="name" aria-hidden="true"><AppIcon name="chevron" :size="14" :stroke="2" class="chev" />{{ r.name }}</span>
              <span class="track mark-track" aria-hidden="true">
                <span class="fill mark-bar" :class="{ 'no-glow': r.name === 'Other' }" :style="{ width: r.width, '--series': r.color }"></span>
              </span>
              <b class="mono count" aria-hidden="true">{{ int(r.count) }}</b>
              <span class="mono share" aria-hidden="true">{{ percent(r.share) }}</span>
            </button>
            <ul v-if="opened.has(r.key)" :id="`inv-${r.key}`" class="types" :aria-label="`${r.name}: largest types`">
              <li v-for="t in r.top" :key="t.type" class="type">
                <RouterLink class="row-link mono tname" :to="resources(connectionId, t.type)" :aria-label="`${t.type}: ${int(t.count)} assets, show in Resources`">{{ t.type }}</RouterLink>
                <span class="mono tcount">{{ int(t.count) }}</span>
              </li>
              <li v-if="r.more" class="cap">
                and {{ r.more }} more type{{ r.more === 1 ? '' : 's' }} in <RouterLink :to="resources(connectionId)">Resources</RouterLink>
              </li>
            </ul>
          </li>
        </ul>
        <p v-else-if="p.covered" class="cap">No inventory scan yet.</p>
      </div>
    </template>
    <div v-else class="loading">
      <div v-for="n in 3" :key="n" class="skeleton sk-row"></div>
    </div>
  </section>
</template>

<style scoped>
.titles {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.title-row {
  display: flex;
  gap: var(--s-10);
  align-items: center;
}

.provider {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.provider + .provider {
  padding-top: var(--s-14);
  border-top: 1px solid var(--border);
}

.prov-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--s-12);
  min-height: 32px;
}

.pname {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
  font-size: 13px;
  font-weight: 600;
}

.nc-dot {
  opacity: 0.4;
}

.nc {
  font-size: 12px;
  color: var(--text-3);
}

.total {
  font-size: 12px;
  color: var(--text-2);
}

.total b {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
}

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

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.sk-row {
  height: 32px;
}

p {
  margin: 0;
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
