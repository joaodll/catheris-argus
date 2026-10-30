<script setup lang="ts">
/**
 * A score's recent trend, 120 × 28 (design-system.md, Sparkline): no axes, y fixed 0 to 100 so
 * two sparklines compare honestly, the line in the band of the latest point, a dot on it. A
 * missing value breaks the line. Decorative: the text alternative sits next to it.
 */
import { computed } from 'vue'
import { scoreColor } from '@/format'

const props = withDefaults(defineProps<{ values: (number | null | undefined)[]; width?: number; height?: number }>(), {
  width: 120,
  height: 28,
})

const PAD = 3
const geometry = computed(() => {
  const n = props.values.length
  const x = (i: number): number => (n <= 1 ? props.width - PAD : PAD + (i * (props.width - 2 * PAD)) / (n - 1))
  const y = (v: number): number => props.height - PAD - (Math.min(100, Math.max(0, v)) / 100) * (props.height - 2 * PAD)
  const segments: string[][] = [[]]
  props.values.forEach((v, i) => {
    if (v == null) segments.push([])
    else segments[segments.length - 1]?.push(`${x(i).toFixed(1)},${y(v).toFixed(1)}`)
  })
  let last: { x: number; y: number; v: number } | null = null
  for (let i = n - 1; i >= 0; i--) {
    const v = props.values[i]
    if (v != null) {
      last = { x: x(i), y: y(v), v }
      break
    }
  }
  return { paths: segments.filter((s) => s.length > 1).map((s) => s.join(' ')), last }
})
</script>

<template>
  <svg :width="props.width" :height="props.height" :viewBox="`0 0 ${props.width} ${props.height}`" aria-hidden="true" class="spark">
    <polyline
      v-for="(pts, i) in geometry.paths"
      :key="i"
      :points="pts"
      class="mark-line"
      :style="{ '--series': scoreColor(geometry.last?.v) }"
      fill="none"
      :stroke="scoreColor(geometry.last?.v)"
      stroke-width="1.5"
      stroke-linejoin="round"
      stroke-linecap="round"
    />
    <circle v-if="geometry.last" :cx="geometry.last.x" :cy="geometry.last.y" r="2.5" :fill="scoreColor(geometry.last.v)" />
  </svg>
</template>

<style scoped>
.spark {
  display: block;
  overflow: visible;
}
</style>
