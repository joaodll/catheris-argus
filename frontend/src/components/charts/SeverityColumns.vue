<script setup lang="ts">
/**
 * Columns split by severity, most severe at the base (spec: palace frontend/0064ccbd,
 * "SeverityColumns"): how long open misconfigurations have been open. Each slot (column, total
 * and label) is one link to the list that reproduces it, well above a 24 px target; its
 * accessible name carries every count. A real zero keeps its link and draws a baseline tick.
 */
import { computed } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { int } from '@/format'
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, type Severity } from '@/views/overview/severity'

export interface SeverityColumn {
  key: string
  label: string
  short: string // under 600 px
  severities: Record<Severity, number>
  total: number
  to: RouteLocationRaw
}

const props = defineProps<{ columns: SeverityColumn[]; noun?: string }>()

const PLOT = 160 // px, the tallest column
const max = computed(() => Math.max(1, ...props.columns.map((c) => c.total)))
const slots = computed(() =>
  props.columns.map((c) => ({
    ...c,
    height: `${Math.round((c.total / max.value) * PLOT)}px`,
    // Bottom up: critical at the base, so the worst never floats.
    segments: SEVERITIES.filter((s) => c.severities[s] > 0).map((s) => ({ severity: s, grow: c.severities[s], color: SEVERITY_COLOR[s] })),
    name: `${c.label}: ${int(c.total)} ${props.noun ?? 'open'}: ${SEVERITIES.map((s) => `${int(c.severities[s])} ${SEVERITY_LABEL[s].toLowerCase()}`).join(', ')}. Show in list.`,
  })),
)
</script>

<template>
  <ol class="cols">
    <li v-for="c in slots" :key="c.key" class="slot">
      <RouterLink class="link" :to="c.to" :aria-label="c.name">
        <span class="total mono" aria-hidden="true">{{ int(c.total) }}</span>
        <span class="plot" aria-hidden="true">
          <span v-if="c.total" class="col" :style="{ height: c.height }">
            <span v-for="seg in c.segments" :key="seg.severity" class="seg mark-col" :style="{ flexGrow: seg.grow, '--series': seg.color }"></span>
          </span>
          <span v-else class="tick"></span>
        </span>
        <span class="label" aria-hidden="true"><span class="long">{{ c.label }}</span><span class="short">{{ c.short }}</span></span>
      </RouterLink>
    </li>
  </ol>
</template>

<style scoped>
.cols {
  display: grid;
  grid-auto-columns: minmax(0, 1fr);
  grid-auto-flow: column;
  margin: 0;
  padding: 0;
  list-style: none;
}

.link {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--s-6);
  height: 100%;
  padding: var(--s-6) var(--s-4) var(--s-8);
  border-radius: var(--r-control);
  color: inherit;
  text-decoration: none;
}

.link:hover {
  background: var(--surface-raised);
}

.total {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
}

.plot {
  display: flex;
  align-items: flex-end;
  justify-content: center;
  width: 100%;
  height: 160px;
  border-bottom: 1px solid var(--border-strong);
}

.col {
  display: flex;
  flex-direction: column-reverse;
  gap: 1px;
  width: min(56px, 72%);
}

.seg {
  min-height: 2px;
}

.seg:last-child {
  border-radius: 3px 3px 0 0;
}

.tick {
  width: min(56px, 72%);
  height: 1px;
  background: var(--border-control);
}

.label {
  font-size: 12px;
  text-align: center;
  color: var(--text-2);
}

.short {
  display: none;
}

@media (max-width: 600px) {
  .long {
    display: none;
  }

  .short {
    display: inline;
  }
}
</style>
