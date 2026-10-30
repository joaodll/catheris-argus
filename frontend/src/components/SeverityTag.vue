<script setup lang="ts">
/**
 * A finding's severity: a square and the word, in the severity colour (design-system.md,
 * Severity tag). `compact` drops the fill (inside a table cell next to a count).
 */
import { computed } from 'vue'
import { SEVERITY_COLOR, SEVERITY_TEXT, type Severity } from '@/views/overview/severity'

const props = defineProps<{ severity: string; compact?: boolean }>()
// The tag says "Info" where the Overview says "Informational": it has to stay short in a row.
const WORD: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' }
const color = computed(() => SEVERITY_COLOR[props.severity as Severity] ?? 'var(--text-2)')
// The word in its text shade (readable over the tag's own tint); the square and fill in the mark colour.
const text = computed(() => SEVERITY_TEXT[props.severity as Severity] ?? 'var(--text-2)')
const word = computed(() => WORD[props.severity as Severity] ?? props.severity)
</script>

<template>
  <span class="sev" :class="{ compact: props.compact }" :style="{ '--sev': color, '--sev-word': text }">
    <span class="square" aria-hidden="true"></span>{{ word }}
  </span>
</template>

<style scoped>
/* CatherIs Platform's severity badge (design-system.md, Severity tag): the word in upper case. */
.sev {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 8px;
  border-radius: var(--r-chip);
  background: color-mix(in srgb, var(--sev) 15%, transparent);
  color: var(--sev-word);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.04em;
  line-height: 1.5;
  text-transform: uppercase;
  white-space: nowrap;
}

.square {
  display: none;
  width: 8px;
  height: 8px;
  background: var(--sev);
}

/* Compact (inside a table): the square and the word, no fill. */
.sev.compact {
  padding: 0;
  background: none;
}

.sev.compact .square {
  display: inline-block;
}
</style>
