<script setup lang="ts">
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import ToolChip from '@/components/ToolChip.vue'
import { int, longDate } from '@/format'
import { attackPaths } from './drill'

const props = defineProps<{ data: Schemas['Overview'] | null; connectionId: number }>()

const cats = computed(() => [...(props.data?.attack_paths_by_category ?? [])].sort((a, b) => b.count - a.count))
const total = computed(() => cats.value.reduce((n, c) => n + c.count, 0))
const max = computed(() => Math.max(1, ...cats.value.map((c) => c.count)))
</script>

<template>
  <section class="card stack" aria-labelledby="cf-h">
    <div class="card-head">
      <div class="titles">
        <div class="title-row"><ToolChip tool="cloudfox" /><h2 id="cf-h" class="h2">Attack paths by category</h2></div>
        <span class="sub">{{ int(total) }} open paths · as of {{ data?.data_through ? longDate(data.data_through) : '…' }}</span>
      </div>
    </div>
    <ul v-if="cats.length" class="cats">
      <li v-for="c in cats" :key="c.category" class="cat">
        <span class="cat-head"><RouterLink class="row-link cat-name" :to="attackPaths(connectionId, { category: c.category })" :aria-label="`${c.category}: ${int(c.count)} open paths, show in Attack paths`">{{ c.category }}</RouterLink><b class="mono">{{ int(c.count) }}</b></span>
        <span class="track mark-track" aria-hidden="true"><span class="fill mark-bar" :style="{ width: `${(c.count / max) * 100}%` }"></span></span>
      </li>
    </ul>
    <p v-else-if="data" class="cap">No open attack paths in the latest scan.</p>
    <div v-else class="skeleton sk-160"></div>
    <div class="providers">
      <span class="lbl">By provider</span>
      <div class="prov">
        <span class="pname"><span class="dot dot-aws mark-dot"></span>AWS</span>
        <span class="track mark-track"><span class="fill mark-bar" :style="{ width: total ? '100%' : '0' }"></span></span>
        <span class="mono pval">{{ int(total) }}</span>
      </div>
      <div class="prov">
        <span class="pname"><span class="dot dot-gcp nc-dot"></span>GCP</span>
        <span class="track mark-track"></span>
        <span class="pval nc">not covered</span>
      </div>
      <div class="prov">
        <span class="pname"><span class="dot dot-oci nc-dot"></span>OCI</span>
        <span class="track mark-track"></span>
        <span class="pval nc">not covered</span>
      </div>
    </div>
    <p class="cap">CloudFox lists permissions, trusts and endpoints; Argus chains them with Steampipe inventory and failing Prowler checks into paths.</p>
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

.cats {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.cat {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding: var(--s-12);
  border: 1px solid var(--border);
  border-radius: var(--r-tile);
  background: var(--tile);
}

.cat-head {
  display: flex;
  justify-content: space-between;
  gap: var(--s-10);
  align-items: baseline;
}

.cat-name {
  font-size: 14px;
  font-weight: 500;
}

.cat-head b {
  font-size: 18px;
  font-weight: 600;
}

.track {
  display: block;
  height: 10px;
  border-radius: 4px;
}

.fill {
  --series: var(--provider-aws);

  display: block;
  height: 100%;
  border-radius: 4px;
}

.nc-dot {
  opacity: 0.4;
}

.providers {
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
  padding-top: var(--s-14);
  border-top: 1px solid var(--border);
}

.prov {
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr) 96px;
  gap: var(--s-12);
  align-items: center;
}

.prov .track {
  height: 8px;
}

.pname {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
}

.pval {
  font-size: 12px;
  text-align: right;
}

.nc {
  color: var(--text-3);
}

p {
  margin: 0;
}
</style>
