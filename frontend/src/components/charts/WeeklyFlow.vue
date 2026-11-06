<script setup lang="ts">
/**
 * Opened against resolved per week (spec: palace frontend/0064ccbd, "WeeklyFlow"; design.md
 * "Opened vs resolved per week: bars about zero"). Opened rise above the zero line, reopened
 * stacked on them as stripes (a pattern, not another colour), resolved fall below it, on one
 * scale. A week before the first count has no data: a gap, never a zero. The current week is
 * partial and outlined dashed.
 *
 * The plot is a picture for sighted readers (aria-hidden); a hidden list gives every week's
 * numbers to a screen reader, and the caption under the plot shows the week under the pointer,
 * the latest week otherwise. Columns are not links: no list filter reproduces an event count.
 */
import { computed, ref } from 'vue'
import { int, shortDate } from '@/format'

export interface FlowWeek {
  week: string // its Monday, YYYY-MM-DD
  partial: boolean
  opened: number | null
  reopened: number | null
  resolved: number | null
}

const props = defineProps<{ weeks: FlowWeek[]; noun: string }>()

const PLOT = 200
const hovered = ref<number | null>(null)

const known = computed(() => props.weeks.filter((w) => w.opened != null))
const scale = computed(() => {
  const up = Math.max(0, ...known.value.map((w) => (w.opened ?? 0) + (w.reopened ?? 0)))
  const down = Math.max(0, ...known.value.map((w) => w.resolved ?? 0))
  const sum = up + down
  return { up, down, px: sum ? PLOT / sum : 0, zero: sum ? (up / sum) * PLOT : PLOT / 2 }
})
const columns = computed(() =>
  props.weeks.map((w, i) => ({
    ...w,
    i,
    label: shortDate(w.week),
    opened: w.opened == null ? null : w.opened * scale.value.px,
    reopened: w.reopened == null ? null : w.reopened * scale.value.px,
    resolved: w.resolved == null ? null : w.resolved * scale.value.px,
    // Every week ≥1150 px, every 2nd ≥600, every 3rd below, counted from the latest.
    every2: (props.weeks.length - 1 - i) % 2 === 0,
    every3: (props.weeks.length - 1 - i) % 3 === 0,
  })),
)

function words(w: FlowWeek): string {
  const when = w.partial ? `This week so far (from ${shortDate(w.week)})` : `Week of ${shortDate(w.week)}`
  if (w.opened == null) return `${when}: no data yet`
  const opened = w.opened + (w.reopened ?? 0)
  return `${when}: ${int(opened)} opened (${int(w.reopened)} reopened), ${int(w.resolved)} resolved`
}

const caption = computed(() => {
  const at = hovered.value ?? props.weeks.length - 1
  const w = props.weeks[at]
  return w ? words(w) : ''
})
</script>

<template>
  <div class="flow">
    <div class="legend" aria-hidden="true">
      <span><span class="sw opened"></span>Opened</span>
      <span><span class="sw reopened"></span>Reopened</span>
      <span><span class="sw resolved"></span>Resolved</span>
    </div>
    <div class="plot" aria-hidden="true" :style="{ '--zero': `${scale.zero}px` }" @mouseleave="hovered = null">
      <span class="zero"></span>
      <span
        v-for="c in columns"
        :key="c.week"
        class="week"
        :class="{ partial: c.partial, every2: c.every2, every3: c.every3 }"
        @mouseenter="hovered = c.i"
      >
        <span class="up">
          <span v-if="c.reopened" class="bar reopened" :style="{ height: `${c.reopened}px` }"></span>
          <span v-if="c.opened" class="bar opened mark-col" :style="{ height: `${c.opened}px`, '--series': 'var(--delta-worse)' }"></span>
        </span>
        <span class="down">
          <span v-if="c.resolved" class="bar resolved mark-col" :style="{ height: `${c.resolved}px`, '--series': 'var(--delta-better)' }"></span>
        </span>
        <span class="tick">{{ c.partial ? 'This week' : c.label }}</span>
      </span>
    </div>
    <p class="caption cap" aria-live="polite">{{ caption }}</p>
    <ul class="sr-only">
      <li v-for="w in weeks" :key="w.week">{{ words(w) }}</li>
    </ul>
  </div>
</template>

<style scoped>
.flow {
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
}

.legend {
  display: flex;
  justify-content: flex-end;
  gap: var(--s-14);
  font-size: 12px;
  color: var(--text-2);
}

.legend > span {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.sw {
  width: 10px;
  height: 10px;
  border-radius: 2px;
}

.opened {
  background: var(--delta-worse);
}

.reopened {
  background: repeating-linear-gradient(45deg, var(--delta-worse) 0 3px, var(--surface) 3px 6px);
}

.resolved {
  background: var(--delta-better);
}

.plot {
  position: relative;
  display: grid;
  grid-auto-columns: minmax(0, 1fr);
  grid-auto-flow: column;
  gap: var(--s-6);
  height: calc(200px + 24px);
}

.zero {
  position: absolute;
  inset: var(--zero) 0 auto;
  height: 1px;
  background: var(--border-strong);
}

.week {
  position: relative;
  display: grid;
  grid-template-rows: var(--zero) calc(200px - var(--zero)) 24px;
  justify-items: center;
}

.week:hover {
  background: var(--surface-raised);
  border-radius: var(--r-control);
}

.week.partial .up,
.week.partial .down {
  outline: 1px dashed var(--border-control);
  outline-offset: 2px;
}

.up {
  display: flex;
  flex-direction: column;
  justify-content: flex-end;
  width: min(28px, 70%);
}

.down {
  display: flex;
  flex-direction: column;
  width: min(28px, 70%);
}

.bar {
  min-height: 1px;
}

.up .bar:first-child {
  border-radius: 3px 3px 0 0;
}

.up .bar:last-child:not(:first-child) {
  border-radius: 0;
}

.down .bar {
  border-radius: 0 0 3px 3px;
}

.tick {
  align-self: end;
  font-size: 11px;
  color: var(--text-3);
  white-space: nowrap;
}

@media (max-width: 1150px) {
  .week:not(.every2) .tick {
    visibility: hidden;
  }
}

@media (max-width: 600px) {
  .week:not(.every3) .tick {
    visibility: hidden;
  }

  .week.every3 .tick {
    visibility: visible;
  }
}

.caption {
  margin: 0;
  min-height: 1.45em;
}
</style>
