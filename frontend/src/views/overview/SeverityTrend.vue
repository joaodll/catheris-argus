<script setup lang="ts">
/**
 * One line per severity over time, with month bands (board D1). 6M: month-ends; 3M: weekly;
 * 1M: daily. The legend shows or hides each severity. The chart itself is the shared
 * LineChart (a missing point breaks the line; drawn in CSS px, never scaled).
 */
import { computed, ref } from 'vue'
import type { Schemas } from '@/api/client'
import { type LineSeries, RANGES, type Range } from '@/components/charts/chart'
import LineChart from '@/components/charts/LineChart.vue'
import RangeToggle from '@/components/charts/RangeToggle.vue'
import { int } from '@/format'
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, type Severity } from './severity'

const props = defineProps<{ data: Schemas['Overview'] | null; range: Range }>()
const emit = defineEmits<{ selectRange: [range: Range] }>()

const hidden = ref<Set<Severity>>(new Set())
function toggle(s: Severity): void {
  const next = new Set(hidden.value)
  if (next.has(s)) next.delete(s)
  else next.add(s)
  hidden.value = next
}

const points = computed(() => props.data?.severity_over_time.points ?? [])
const series = computed<LineSeries[]>(() =>
  SEVERITIES.filter((s) => !hidden.value.has(s)).map((s) => ({
    key: s,
    label: SEVERITY_LABEL[s],
    color: SEVERITY_COLOR[s],
    values: points.value.map((p) => p[s]),
  })),
)
const aria = computed(() => {
  const last = points.value[points.value.length - 1]
  if (!last) return 'No findings history yet'
  return `Open failed findings by severity over ${points.value.length} points; latest: ${SEVERITIES.map((s) => `${SEVERITY_LABEL[s]} ${int(last[s])}`).join(', ')}`
})
</script>

<template>
  <div class="trend">
    <div class="head">
      <div class="titles"><span class="lbl">Findings severity over time</span><span class="sub">Open failed findings · {{ RANGES.find((r) => r.id === props.range)?.label }}</span></div>
      <RangeToggle :range="props.range" @select="emit('selectRange', $event)" />
    </div>
    <LineChart :dates="points.map((p) => p.date)" :series="series" :format="int" :label="aria" />
    <div role="group" aria-label="Severities shown" class="legend">
      <button
        v-for="s in SEVERITIES"
        :key="s"
        type="button"
        class="legend-item"
        :class="{ off: hidden.has(s) }"
        :aria-pressed="!hidden.has(s)"
        @click="toggle(s)"
      >
        <span class="dot mark-dot" :style="{ '--series': SEVERITY_COLOR[s] }"></span>{{ SEVERITY_LABEL[s] }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.trend {
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
}

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

.legend {
  display: flex;
  gap: var(--s-6);
  flex-wrap: wrap;
  align-self: flex-start;
  padding: var(--s-4);
  background: var(--tile);
  border: 1px solid var(--border);
  border-radius: var(--r-tile);
}

.legend-item {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
  min-height: 36px;
  padding: 0 var(--s-12);
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text);
  font-size: 13px;
  cursor: pointer;
}

.legend-item.off {
  opacity: 0.45;
  text-decoration: line-through;
}
</style>
