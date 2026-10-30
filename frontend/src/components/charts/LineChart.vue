<script setup lang="ts">
/**
 * Lines over time with month bands: the one SVG line chart (the Overview's severity trend, a
 * framework's score). A missing value breaks the line: it is never drawn as zero. Drawn in CSS
 * px at the card's width, never scaled: the height and the text stay the same on any screen
 * and follow the browser zoom (design-system.md, Chart marks).
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { monthName, shortDate } from '@/format'
import type { LineSeries } from './chart'

const props = defineProps<{
  dates: string[] // ISO days, oldest first
  series: LineSeries[]
  format: (value: number) => string
  label: string // the chart's text alternative
  yMax?: number // a fixed axis (scores: 100); otherwise a round number above the data
  guides?: number[] // dashed reference lines, labelled at the right edge
}>()

const LEFT = 60
const HEIGHT = 270
const TOP = 30
const BOTTOM = 240

/** The plot's width in px: measured from the card, 1000 until the first measure. */
const chart = ref<HTMLElement | null>(null)
const width = ref(1000)
const right = computed(() => width.value - (props.guides?.length ? 36 : 20))
let observer: ResizeObserver | null = null
onMounted(() => {
  if (!chart.value) return
  observer = new ResizeObserver(([entry]) => {
    if (entry) width.value = Math.floor(entry.contentRect.width)
  })
  observer.observe(chart.value)
})
onBeforeUnmount(() => observer?.disconnect())

const step = computed(() => (right.value - LEFT) / Math.max(props.dates.length, 1))
const xAt = (i: number): number => LEFT + (i + 0.5) * step.value

const max = computed(() => {
  if (props.yMax != null) return props.yMax
  let top = 0
  for (const s of props.series) for (const v of s.values) top = Math.max(top, v ?? 0)
  if (top <= 0) return 4
  const quarter = top / 4
  const magnitude = 10 ** Math.floor(Math.log10(quarter))
  const nice = [1, 2, 2.5, 5, 10].map((m) => m * magnitude).find((m) => m >= quarter) ?? quarter
  return Math.max(4, nice * 4)
})
const yAt = (v: number): number => BOTTOM - (v / max.value) * (BOTTOM - TOP)
const ticks = computed(() => [0, 1, 2, 3, 4].map((i) => ({ value: (max.value / 4) * i, y: yAt((max.value / 4) * i) })))
const guideLines = computed(() => (props.guides ?? []).map((g) => ({ value: g, y: yAt(g) })))

const bands = computed(() => {
  const out: { label: string; x: number; w: number; even: boolean }[] = []
  props.dates.forEach((d, i) => {
    const month = d.slice(0, 7)
    const last = out[out.length - 1]
    if (last && last.label === month) last.w += step.value
    else out.push({ label: month, x: LEFT + i * step.value, w: step.value, even: out.length % 2 === 0 })
  })
  return out.map((b) => ({ ...b, label: monthName(b.label) }))
})

const lines = computed(() =>
  props.series.map((s) => {
    const segments: string[][] = [[]]
    const dots: { x: number; y: number; color: string; title: string }[] = []
    props.dates.forEach((d, i) => {
      const v = s.values[i]
      if (v == null) {
        segments.push([])
        return
      }
      const x = xAt(i)
      const y = yAt(v)
      segments[segments.length - 1]?.push(`${x.toFixed(1)},${y.toFixed(1)}`)
      dots.push({ x, y, color: s.dotColors?.[i] ?? s.color, title: `${s.label} on ${shortDate(d)}: ${props.format(v)}` })
    })
    return { ...s, paths: segments.filter((g) => g.length > 1).map((g) => g.join(' ')), dots }
  }),
)

const labels = computed(() => props.dates.map((d, i) => ({ x: xAt(i), text: shortDate(d) })))
const labelEvery = computed(() => Math.max(1, Math.ceil(props.dates.length / 8)))
</script>

<template>
  <div class="scroll">
    <div ref="chart" class="chart">
      <svg :viewBox="`0 0 ${width} ${HEIGHT}`" :width="width" :height="HEIGHT" role="img" :aria-label="props.label">
        <g v-for="b in bands" :key="`${b.label}-${b.x}`">
          <rect :x="b.x" y="0" :width="b.w" :height="BOTTOM" :class="b.even ? 'band-even' : 'band-odd'" />
          <line :x1="b.x" :x2="b.x" y1="0" :y2="BOTTOM" class="band-sep" />
          <text :x="b.x + b.w / 2" y="16" text-anchor="middle" class="band-label">{{ b.label }}</text>
        </g>
        <g v-for="t in ticks" :key="t.value">
          <line :x1="LEFT" :x2="right" :y1="t.y" :y2="t.y" class="grid" />
          <text :x="LEFT - 10" :y="t.y + 4" text-anchor="end" class="tick">{{ props.format(t.value) }}</text>
        </g>
        <g v-for="g in guideLines" :key="`guide-${g.value}`">
          <line :x1="LEFT" :x2="right" :y1="g.y" :y2="g.y" class="guide" />
          <text :x="right + 6" :y="g.y + 4" class="tick">{{ props.format(g.value) }}</text>
        </g>
        <g v-for="line in lines" :key="line.key">
          <polyline
            v-for="(pts, i) in line.paths"
            :key="i"
            :points="pts"
            class="mark-line"
            :style="{ '--series': line.color }"
            fill="none"
            :stroke="line.color"
            stroke-width="2.5"
            stroke-linejoin="round"
            stroke-linecap="round"
          />
          <circle v-for="d in line.dots" :key="`${d.x}`" :cx="d.x" :cy="d.y" r="3.5" :fill="d.color" class="dot-edge"><title>{{ d.title }}</title></circle>
        </g>
        <template v-for="(l, i) in labels" :key="i">
          <text v-if="i % labelEvery === 0 || i === labels.length - 1" :x="l.x" y="262" text-anchor="middle" class="x-label">{{ l.text }}</text>
        </template>
      </svg>
    </div>
  </div>
</template>

<style scoped>
.scroll {
  overflow-x: auto;
}

.chart {
  min-width: 640px;
}

svg {
  display: block;
  overflow: visible;
}

.band-even {
  fill: var(--chart-band);
}

.band-odd {
  fill: transparent;
}

.band-sep {
  stroke: var(--tile-border);
}

.band-label {
  fill: var(--text-chip);
  font-size: 12px;
  font-weight: 600;
  font-family: var(--font-mono);
}

.grid {
  stroke: var(--border);
}

.guide {
  stroke: var(--tile-border);
  stroke-dasharray: 4 4;
}

.tick {
  fill: var(--text-3);
  font-size: 11px;
  font-family: var(--font-mono);
}

.dot-edge {
  stroke: var(--surface);
  stroke-width: 1.5;
}

.x-label {
  fill: var(--text-chip);
  font-size: 12px;
  font-family: var(--font-sans);
}
</style>
