<script setup lang="ts">
/**
 * Steampipe inventory: assets by category, per provider (round 5, frontend/1d636dd5). One bar
 * scale across providers, so a bigger estate shows longer bars.
 */
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import ToolChip from '@/components/ToolChip.vue'
import { int, longDate } from '@/format'
import { byProvider } from './assetTypes'
import CategoryRows from './CategoryRows.vue'
import { resources } from './drill'

const props = defineProps<{ data: Schemas['Overview'] | null; connectionId: number }>()

const countOf = computed(() => new Map((props.data?.inventory.by_type ?? []).map((t) => [t.type, t.count])))
const providers = computed(() => byProvider(props.data?.inventory.by_type ?? [], props.data?.coverage ?? {}))
const max = computed(() => Math.max(1, ...providers.value.flatMap((p) => p.groups.map((g) => g.count))))
const typeLink = (type: string) => resources(props.connectionId, type)
</script>

<template>
  <section class="card stack" aria-labelledby="inv-h">
    <div class="card-head">
      <div class="titles">
        <div class="title-row"><ToolChip tool="steampipe" /><h2 id="inv-h" class="h2">Inventory</h2></div>
        <span class="sub">{{ int(data?.kpis.assets.value) }} assets · as of {{ data?.data_through ? longDate(data.data_through) : '…' }}</span>
      </div>
    </div>
    <span class="lbl">Assets by category, per provider</span>
    <template v-if="data">
      <div v-for="p in providers" :key="p.id" class="provider">
        <div class="prov-head">
          <span class="pname"><span class="dot" :class="p.covered ? ['mark-dot', `dot-${p.id}`] : ['nc-dot', `dot-${p.id}`]"></span>{{ p.name }}</span>
          <span v-if="!p.covered" class="nc">not covered</span>
          <span v-else class="total"><b class="mono">{{ p.total == null ? '—' : int(p.total) }}</b> assets</span>
        </div>
        <CategoryRows
          v-if="p.groups.length"
          :id="`inv-${p.id}`"
          :label="`${p.name} assets by category`"
          :groups="p.groups"
          :counts="countOf"
          :max="max"
          :total="p.total ?? 0"
          :type-link="typeLink"
          :more-link="resources(connectionId)"
          more-where="Resources"
        />
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
</style>
