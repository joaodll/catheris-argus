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
  // Findings: opened (reopened stacked on it) above zero, resolved below.
  opened?: number | null
  reopened?: number | null
  resolved?: number | null
  // Assets (the Resources summary): added above zero, removed below, and how many accounts had
  // their first scan that week (their resources are their starting inventory, not added).
  added?: number | null
  removed?: number | null
  baseline?: number | null
}

const props = withDefaults(defineProps<{ weeks: FlowWeek[]; noun: string; kind?: 'findings' | 'assets' }>(), { kind: 'findings' })

const PLOT = 200
const hovered = ref<number | null>(null)
const assets = computed(() => props.kind === 'assets')

/** The kind's three numbers of a week: rising, stacked on the rising one, falling. */
function parts(w: FlowWeek): { up: number | null; stack: number | null; down: number | null } {
  return assets.value ? { up: w.added ?? null, stack: null, down: w.removed ?? null } : { up: w.opened ?? null, stack: w.reopened ?? null, down: w.resolved ?? null }
}

const known = computed(() => props.weeks.map(parts).filter((p) => p.up != null))
const scale = computed(() => {
  const up = Math.max(0, ...known.value.map((p) => (p.up ?? 0) + (p.stack ?? 0)))
  const down = Math.max(0, ...known.value.map((p) => p.down ?? 0))
  const sum = up + down
  return { up, down, px: sum ? PLOT / sum : 0, zero: sum ? (up / sum) * PLOT : PLOT / 2 }
})
const columns = computed(() =>
  props.weeks.map((w, i) => {
    const p = parts(w)
    return {
      week: w.week,
      partial: w.partial,
      i,
      label: shortDate(w.week),
      up: p.up == null ? null : p.up * scale.value.px,
      stack: p.stack == null ? null : p.stack * scale.value.px,
      down: p.down == null ? null : p.down * scale.value.px,
      baseline: Boolean(w.baseline),
      // Every week ≥1150 px, every 2nd ≥600, every 3rd below, counted from the latest.
      every2: (props.weeks.length - 1 - i) % 2 === 0,
      every3: (props.weeks.length - 1 - i) % 3 === 0,
    }
  }),
)

function words(w: FlowWeek): string {
  const when = w.partial ? `This week so far (from ${shortDate(w.week)})` : `Week of ${shortDate(w.week)}`
  const p = parts(w)
  if (p.up == null) return `${when}: no data yet`
  if (assets.value) {
    const first = w.baseline ? `first scan of ${int(w.baseline)} account${w.baseline === 1 ? '' : 's'}; ` : ''
    return `${when}: ${first}${int(p.up)} added, ${int(p.down)} removed`
  }
  const opened = p.up + (p.stack ?? 0)
  return `${when}: ${int(opened)} opened (${int(p.stack)} reopened), ${int(p.down)} resolved`
}

const caption = computed(() => {
  const at = hovered.value ?? props.weeks.length - 1
  const w = props.weeks[at]
  return w ? words(w) : ''
})
</script>

<template>
  <div class="flow" :class="{ assets }">
    <div class="legend" aria-hidden="true">
      <template v-if="assets">
        <span><span class="sw added"></span>Added</span>
        <span><span class="sw removed"></span>Removed</span>
        <span><span class="first-dot"></span>First scan</span>
      </template>
      <template v-else>
        <span><span class="sw opened"></span>Opened</span>
        <span><span class="sw reopened"></span>Reopened</span>
        <span><span class="sw resolved"></span>Resolved</span>
      </template>
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
          <span v-if="c.baseline" class="first-dot mark"></span>
          <span v-if="c.stack" class="bar reopened" :style="{ height: `${c.stack}px` }"></span>
          <span
            v-if="c.up"
            class="bar mark-col"
            :class="assets ? 'added' : 'opened'"
            :style="{ height: `${c.up}px`, '--series': assets ? 'var(--tool-steampipe)' : 'var(--delta-worse)' }"
          ></span>
        </span>
        <span class="down">
          <span
            v-if="c.down"
            class="bar mark-col"
            :class="assets ? 'removed' : 'resolved'"
            :style="{ height: `${c.down}px`, '--series': assets ? 'var(--text-3)' : 'var(--delta-better)' }"
          ></span>
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

.added {
  background: var(--tool-steampipe);
}

.removed {
  background: var(--text-3);
}

/* A week with an account's first scan: a dot above the zero line, named in the caption. */
.first-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--text-3);
}

.legend .first-dot {
  display: inline-block;
}

.first-dot.mark {
  align-self: center;
  margin-bottom: var(--s-4);
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

.up .bar:first-child,
.up .first-dot + .bar {
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
