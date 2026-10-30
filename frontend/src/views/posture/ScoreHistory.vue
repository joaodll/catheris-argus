<script setup lang="ts">
/**
 * A framework's score over time (screens.md E10, item 3): the shared LineChart on a fixed 0 to
 * 100 axis with guides at the score bands, then the month-over-month row. The line takes the
 * band of the latest score; each dot its own point's band (design-system.md, Score chart).
 */
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import { type LineSeries, RANGES, type Range } from '@/components/charts/chart'
import LineChart from '@/components/charts/LineChart.vue'
import RangeToggle from '@/components/charts/RangeToggle.vue'
import { decimal, monthName, scoreColor } from '@/format'
import { scoreChange } from './compliance'

const props = defineProps<{ detail: Schemas['FrameworkDetail'] | null; range: Range; scope: string }>()
const emit = defineEmits<{ selectRange: [range: Range] }>()

const points = computed(() => props.detail?.series ?? [])
const series = computed<LineSeries[]>(() => {
  const last = points.value[points.value.length - 1]
  return [
    {
      key: 'score',
      label: 'Score',
      color: scoreColor(last?.score),
      values: points.value.map((p) => p.score),
      dotColors: points.value.map((p) => scoreColor(p.score)),
    },
  ]
})
const aria = computed(() => {
  const last = points.value[points.value.length - 1]
  if (!last) return 'No score history in this range'
  return `Score over ${points.value.length} points; latest ${decimal(last.score)} percent on ${last.date}`
})
const months = computed(() => props.detail?.month_table ?? [])
const percent = (v: number): string => decimal(v).replace(/\.0$/, '')
</script>

<template>
  <section class="card stack" aria-labelledby="score-h">
    <div class="head">
      <div class="titles">
        <h2 id="score-h" class="h2">Score over time</h2>
        <span class="cap">{{ props.scope }} · {{ RANGES.find((r) => r.id === props.range)?.label }}</span>
      </div>
      <RangeToggle :range="props.range" @select="emit('selectRange', $event)" />
    </div>
    <div v-if="!props.detail" class="skeleton sk-270" aria-busy="true"></div>
    <p v-else-if="points.length === 0" class="cap empty">No score for {{ props.scope }} in this range.</p>
    <LineChart v-else :dates="points.map((p) => p.date)" :series="series" :format="percent" :label="aria" :y-max="100" :guides="[80, 70, 60]" />

    <div v-if="props.detail" class="mom">
      <div class="mom-head">
        <span class="lbl">Month over month</span>
        <span class="sub">Score at month end, and change from the month before · <span class="better">▲ higher score</span> · <span class="worse">▼ lower score</span></span>
      </div>
      <div class="scroll">
        <table class="grid">
          <caption class="sr-only">Score at each month end</caption>
          <thead>
            <tr><th scope="col" class="first">Month</th><th v-for="m in months" :key="m.month" scope="col">{{ monthName(m.month) }}</th></tr>
          </thead>
          <tbody>
            <tr>
              <th scope="row" class="first">Score</th>
              <td v-for="m in months" :key="m.month">
                <template v-if="m.score != null">
                  <span class="dot mark-dot" :style="{ '--series': scoreColor(m.score) }"></span><b class="mono">{{ decimal(m.score) }}</b>
                  <span v-if="m.change != null" class="mono d" :style="{ color: scoreChange(m.change).color }" :aria-label="scoreChange(m.change).label">{{ scoreChange(m.change).text }}</span>
                </template>
                <span v-else class="soft" aria-label="No scan">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>

<style scoped>
.head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--s-12);
  flex-wrap: wrap;
}

.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.sk-270 {
  height: 270px;
}

.empty {
  padding: var(--s-24) 0;
}

.mom {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding-top: var(--s-14);
  border-top: 1px solid var(--border);
}

.mom-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: var(--s-12);
  flex-wrap: wrap;
}

.better {
  color: var(--delta-better);
}

.worse {
  color: var(--delta-worse);
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
  white-space: nowrap;
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

.first {
  width: 140px;
  text-align: left !important;
  font-size: 13px;
}

.dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  margin-right: 6px;
  border-radius: 999px;
  vertical-align: middle;
}

td b {
  font-size: 13px;
  font-weight: 600;
}

.d {
  margin-left: 6px;
  font-size: 11px;
}

.soft {
  color: var(--text-3);
}
</style>
