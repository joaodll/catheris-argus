<script setup lang="ts">
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import { int, monthName, signed } from '@/format'
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL } from './severity'

const props = defineProps<{ data: Schemas['Overview'] | null }>()
const months = computed(() => props.data?.severity_over_time.month_table ?? [])

function change(value: number | null | undefined): { text: string; color: string; sign: string } {
  if (value == null) return { text: '', color: 'var(--text-3)', sign: '' }
  if (value === 0) return { text: '±0', color: 'var(--text-3)', sign: '' }
  return value > 0
    ? { text: signed(value), color: 'var(--delta-worse)', sign: '▲' }
    : { text: signed(value), color: 'var(--delta-better)', sign: '▼' }
}

function totalChange(i: number): number | null {
  const now = months.value[i]
  const before = months.value[i - 1]
  return now && before ? now.total - before.total : null
}
</script>

<template>
  <div class="mom">
    <div class="head">
      <span class="lbl">Month over month</span>
      <span class="sub">Open failed findings at month end, and change from the month before · <span class="worse">▲ more findings</span> · <span class="better">▼ fewer findings</span></span>
    </div>
    <div class="scroll">
      <table v-if="months.length" class="grid">
        <caption class="sr-only">Open failed findings by severity at each month end</caption>
        <thead>
          <tr><th scope="col" class="first">Severity</th><th v-for="m in months" :key="m.month" scope="col">{{ monthName(m.month) }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in SEVERITIES" :key="s">
            <th scope="row" class="first"><span class="dot mark-dot" :style="{ '--series': SEVERITY_COLOR[s] }"></span>{{ SEVERITY_LABEL[s] }}</th>
            <td v-for="m in months" :key="m.month">
              <b class="mono">{{ int(m.values[s]) }}</b>
              <span class="mono d" :style="{ color: change(m.change?.[s]).color }">{{ change(m.change?.[s]).sign }}{{ change(m.change?.[s]).text }}</span>
            </td>
          </tr>
          <tr class="total">
            <th scope="row" class="first">Total</th>
            <td v-for="(m, i) in months" :key="m.month">
              <b class="mono">{{ int(m.total) }}</b>
              <span class="mono d" :style="{ color: change(totalChange(i)).color }">{{ change(totalChange(i)).sign }}{{ change(totalChange(i)).text }}</span>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="cap">No month-end history yet.</p>
    </div>
  </div>
</template>

<style scoped>
.mom {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding-top: var(--s-14);
  border-top: 1px solid var(--border);
}

.head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: var(--s-12);
  flex-wrap: wrap;
}

.worse {
  color: var(--delta-worse);
}

.better {
  color: var(--delta-better);
}

.scroll {
  overflow-x: auto;
}

.grid {
  width: 100%;
  min-width: 640px;
  border-collapse: collapse;
}

.grid th,
.grid td {
  padding: 0 3px;
  height: 36px;
  text-align: center;
  font-weight: 400;
}

.grid thead th {
  height: auto;
  padding: 6px 3px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  font-weight: 600;
  color: var(--text-chip);
}

.grid thead th.first {
  font-size: 11px;
  font-weight: 400;
  color: var(--text-3);
}

.grid tbody tr {
  border-bottom: 1px solid var(--tile-border);
}

.first {
  width: 140px;
  text-align: left !important;
  font-size: 13px;
  white-space: nowrap;
}

.first .dot {
  margin-right: var(--s-8);
}

td b {
  font-size: 13px;
  font-weight: 600;
}

.d {
  margin-left: 6px;
  font-size: 11px;
}

.total {
  border-top: 1px solid var(--border-strong);
}

.total th {
  font-weight: 600 !important;
}
</style>
