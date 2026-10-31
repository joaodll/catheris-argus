<script setup lang="ts">
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import { deltaColor, int, monthName, percent, signed } from '@/format'

const props = defineProps<{ data: Schemas['Overview'] | null }>()

const R = 70
const C = 2 * Math.PI * R
const checks = computed(() => props.data?.check_results ?? null)
const total = computed(() => {
  const c = checks.value
  if (!c || c.passed == null) return null
  return (c.passed ?? 0) + (c.failed ?? 0) + (c.muted ?? 0)
})

/** Donut arcs, drawn pass, fail, muted from the top, clockwise. */
const arcs = computed(() => {
  const c = checks.value
  if (!c || !total.value) return []
  let offset = 0
  return [
    { key: 'pass', color: 'var(--pass)', n: c.passed ?? 0 },
    { key: 'fail', color: 'var(--sev-critical)', n: c.failed ?? 0 },
    { key: 'muted', color: 'var(--muted)', n: c.muted ?? 0 },
  ].map((s) => {
    const length = (s.n / (total.value ?? 1)) * C
    const arc = { ...s, dash: `${length} ${C - length}`, offset: -offset }
    offset += length
    return arc
  })
})

const rows = computed(() => {
  const c = checks.value
  if (!c) return []
  const t = total.value ?? 0
  return [
    { name: 'Pass', color: 'var(--pass)', n: c.passed },
    { name: 'Fail', color: 'var(--sev-critical)', n: c.failed },
    { name: 'Muted', color: 'var(--muted)', n: c.muted },
  ].map((r) => ({ ...r, share: r.n == null || !t ? null : (r.n / t) * 100 }))
})

const months = computed(() => props.data?.check_results.monthly_pass_rate ?? [])
// One month of pass rates has no change to show ("±0 pts since Oct"): the framework page's words.
const enoughMonths = computed(() => months.value.filter((m) => m.pass_rate != null).length >= 2)
const monthChange = computed(() => {
  const m = months.value
  const a = m[0]?.pass_rate
  const b = m[m.length - 1]?.pass_rate
  return a == null || b == null ? null : b - a
})
</script>

<template>
  <div class="block">
    <span class="lbl">Check results</span>
    <div v-if="checks && total" class="donut-row">
      <svg width="190" height="190" viewBox="0 0 200 200" role="img" :aria-label="`Pass rate ${percent(checks.pass_rate)} of ${int(total)} checks`" class="donut">
        <g transform="rotate(-90 100 100)" fill="none" stroke-width="22">
          <circle cx="100" cy="100" :r="R" stroke="var(--track)" />
          <circle
            v-for="a in arcs"
            :key="a.key"
            cx="100"
            cy="100"
            :r="R"
            class="mark-line"
            :class="{ 'no-glow': a.key === 'muted' }"
            :style="{ '--series': a.color }"
            :stroke="a.color"
            :stroke-dasharray="a.dash"
            :stroke-dashoffset="a.offset"
          />
        </g>
        <text x="100" y="96" text-anchor="middle" class="center">{{ percent(checks.pass_rate) }}</text>
        <text x="100" y="116" text-anchor="middle" class="center-sub">pass rate</text>
        <text x="100" y="134" text-anchor="middle" class="center-count">{{ int(total) }} checks</text>
      </svg>
      <ul class="legend">
        <li v-for="r in rows" :key="r.name" class="legend-row">
          <span class="dot mark-dot" :class="{ 'no-glow': r.name === 'Muted' }" :style="{ '--series': r.color }"></span>
          <span>{{ r.name }}</span>
          <b class="mono">{{ int(r.n) }}</b>
          <span class="mono share">{{ percent(r.share) }}</span>
        </li>
        <li class="manual cap">{{ int(checks.manual) }} manual, not scored</li>
      </ul>
    </div>
    <p v-else-if="data" class="cap">No Prowler check results yet.</p>
    <div v-else class="skeleton sk-190"></div>

    <div class="history">
      <div class="history-head">
        <span class="sub">Pass rate by month · last 6 months</span>
        <span v-if="data && !enoughMonths" class="sub">Needs two months of history</span>
        <span v-else-if="monthChange != null" class="mono change" :style="{ color: deltaColor(monthChange, true) }">
          {{ signed(monthChange, 1) }} pts since {{ monthName(months[0]?.month ?? '') }}
        </span>
      </div>
      <div class="scroll">
        <ol class="columns" aria-label="Pass rate at the end of each month">
          <li v-for="(m, i) in months" :key="m.month" :title="`${monthName(m.month)}: ${percent(m.pass_rate)} pass${i === months.length - 1 ? ' (month to date)' : ''}`" class="col-item">
            <div class="col" :class="{ current: i === months.length - 1 }">
              <div class="seg seg-fail mark-col" :style="{ flexGrow: m.pass_rate == null ? 0 : 100 - m.pass_rate }"></div>
              <div class="seg seg-pass mark-col" :style="{ flexGrow: m.pass_rate ?? 0 }"></div>
            </div>
            <b class="mono pct">{{ m.pass_rate == null ? '—' : `${Math.round(m.pass_rate)}%` }}</b>
            <span class="m">{{ monthName(m.month) }}</span>
          </li>
        </ol>
      </div>
    </div>
  </div>
</template>

<style scoped>
.block {
  display: flex;
  flex-direction: column;
  gap: var(--s-14);
  min-width: 0;
}

.donut-row {
  display: flex;
  gap: var(--s-24);
  align-items: center;
  flex-wrap: wrap;
}

.donut {
  flex-shrink: 0;
}

.center {
  fill: var(--text);
  font-size: 32px;
  font-weight: 600;
  font-family: var(--font-sans);
}

.center-sub {
  fill: var(--text-2);
  font-size: 12px;
  font-family: var(--font-sans);
}

.center-count {
  fill: var(--text-3);
  font-size: 11px;
  font-family: var(--font-mono);
}

.legend {
  flex: 1;
  min-width: 220px;
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.legend-row {
  display: grid;
  grid-template-columns: 12px minmax(0, 1fr) auto 56px;
  gap: var(--s-10);
  align-items: center;
  min-height: 40px;
  padding: 0 var(--s-10);
  border-radius: var(--r-control);
  font-size: 13px;
}

.legend-row b {
  font-weight: 600;
}

.share {
  font-size: 12px;
  color: var(--text-3);
  text-align: right;
}

.manual {
  padding: var(--s-4) var(--s-10) 0;
}

.history {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding-top: var(--s-12);
  border-top: 1px solid var(--border);
}

.history-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: var(--s-8);
  flex-wrap: wrap;
}

.change {
  font-size: 12px;
}

.scroll {
  overflow-x: auto;
}

.columns {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(6, minmax(40px, 1fr));
  gap: var(--s-10);
  min-width: 300px;
}

.col-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
}

.col {
  width: 100%;
  max-width: 40px;
  height: 64px;
  display: flex;
  flex-direction: column;
  gap: 1px;
  border-radius: 4px;
  overflow: hidden;
}

.col.current {
  outline: 1px dashed var(--tile-current);
  outline-offset: 2px;
}

.seg {
  flex-basis: 0;
}

.seg-fail {
  --series: var(--sev-critical);
}

.seg-pass {
  --series: var(--pass);
}

.pct {
  font-size: 11px;
  font-weight: 600;
}

.m {
  font-size: 10px;
  color: var(--text-3);
}
</style>
