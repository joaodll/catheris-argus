<script setup lang="ts">
/**
 * Card B's count pill (the Security Map; spec frontend/4242ef35): open misconfigurations, tinted
 * in the worst severity's colour, with its square. The words (count and severity) are in the
 * card's tooltip, the List and the panel, so the pill is never the only carrier. `base` is the
 * surface it sits on (a card on the canvas by default).
 */
import { computed } from 'vue'
import type { Severity } from '@/views/overview/severity'
import { sevToken } from './mapFacts'

const props = defineProps<{ count: string; severity: Severity; base?: string }>()
const token = computed(() => sevToken(props.severity))
</script>

<template>
  <span class="count-pill" :style="{ '--sev': `var(--sev-${token})`, '--sev-word': `var(--sev-${token}-text)`, '--pill-base': base ?? 'var(--graph-node)' }">
    <span class="sq"></span><span class="n mono">{{ count }}</span>
  </span>
</template>

<style scoped>
.count-pill {
  flex: none;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 20px;
  min-width: 28px;
  padding: 0 7px;
  border-radius: var(--r-pill);
  background: color-mix(in srgb, var(--sev) 12%, var(--pill-base));
  border: 1px solid color-mix(in srgb, var(--sev) 45%, transparent);
  transition: opacity 160ms;
}

.sq {
  width: 8px;
  height: 8px;
  background: var(--sev);
}

.n {
  font-size: 11.5px;
  font-weight: 700;
  color: var(--sev-word);
}
</style>
