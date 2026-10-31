<script setup lang="ts">
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import { int } from '@/format'
import { failedFindings } from './drill'
import { SEVERITY_COLOR, SEVERITY_LABEL, type Severity } from './severity'

const props = defineProps<{ data: Schemas['Overview'] | null; connectionId: number }>()

const rows = computed(() => {
  const list = props.data?.failed_by_severity ?? []
  const max = Math.max(1, ...list.map((s) => s.value ?? 0))
  return list.map((s) => ({
    ...s,
    name: SEVERITY_LABEL[s.severity as Severity] ?? s.severity,
    color: SEVERITY_COLOR[s.severity as Severity] ?? 'var(--text-3)',
    width: `${Math.max(((s.value ?? 0) / max) * 100, 0.8)}%`,
    to: failedFindings(props.connectionId, s.severity as Severity),
  }))
})
const total = computed(() => rows.value.reduce((n, r) => n + (r.value ?? 0), 0))
</script>

<template>
  <div class="block">
    <div class="head">
      <span class="lbl">Failed findings by severity</span>
      <span class="open"><b class="mono">{{ int(total) }}</b> open</span>
    </div>
    <div class="scroll">
      <table class="bars">
        <caption class="sr-only">Open failed findings by severity in the latest scan</caption>
        <thead>
          <tr><th scope="col">Severity</th><th scope="col"><span class="sr-only">Share</span></th><th scope="col" class="r">Open</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.severity">
            <th scope="row">
              <span class="dot mark-dot" :style="{ '--series': r.color }"></span>
              <RouterLink class="row-link sev" :to="r.to" :aria-label="`${r.name}: ${int(r.value)} open, show in Misconfigurations`">{{ r.name }}</RouterLink>
            </th>
            <td><span class="track mark-track"><span class="fill mark-bar" :style="{ width: r.width, '--series': r.color }"></span></span></td>
            <td class="r mono count">{{ int(r.value) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="cap">Open failed findings in the latest scan.</p>
  </div>
</template>

<style scoped>
.block {
  display: flex;
  flex-direction: column;
  gap: var(--s-14);
  min-width: 0;
}

.head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: var(--s-12);
  flex-wrap: wrap;
}

.open {
  font-size: 13px;
  color: var(--text-chip);
}

.open b {
  color: var(--text);
  font-weight: 600;
}

.scroll {
  overflow-x: auto;
}

.bars {
  width: 100%;
  min-width: 300px;
  border-collapse: collapse;
}

.bars th,
.bars td {
  padding: 0 6px;
  font-weight: 400;
}

.sev {
  font-size: inherit;
  font-weight: inherit;
}

.bars thead th {
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
  font-size: 11px;
  color: var(--text-3);
  text-align: left;
}

.bars tbody tr {
  height: 48px;
}

.bars tbody th {
  width: 130px;
  text-align: left;
  font-size: 13px;
  white-space: nowrap;
}

.bars tbody th .dot {
  margin-right: var(--s-8);
}

.r {
  text-align: right !important;
}

.track {
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
  width: 64px;
  font-size: 15px;
  font-weight: 600;
}

p {
  margin: 0;
}
</style>
