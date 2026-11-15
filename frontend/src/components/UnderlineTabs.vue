<script setup lang="ts" generic="T extends string">
/**
 * Underline tabs (owner's decision 2026-11-05; spec in the palace, frontend/0064ccbd): the
 * Investigate screens' Summary | List and the map panel's tabs (frontend/d37cd13b). The caller
 * owns the panels (ids `<idPrefix>-<value>`) and where the choice is kept; this only reports a
 * choice. Arrow keys move and choose, Home and End jump; only the chosen tab is in the tab order.
 */
import { nextTick, ref } from 'vue'

// `compact`: tighter tabs for a side panel (the map's, 400 px wide).
const props = defineProps<{ modelValue: T; tabs: readonly { value: T; label: string }[]; label: string; idPrefix: string; compact?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [tab: T] }>()

const buttons = ref<HTMLButtonElement[]>([])
const at = (tab: T): number => props.tabs.findIndex((t) => t.value === tab)

async function choose(tab: T, focus = false): Promise<void> {
  if (tab !== props.modelValue) emit('update:modelValue', tab)
  if (focus) {
    await nextTick()
    buttons.value[at(tab)]?.focus()
  }
}

function onKey(event: KeyboardEvent): void {
  const here = at(props.modelValue)
  const n = props.tabs.length
  const moves: Record<string, number> = { ArrowRight: here + 1, ArrowLeft: here - 1, Home: 0, End: n - 1 }
  const move = moves[event.key]
  if (move === undefined) return
  event.preventDefault()
  const next = props.tabs[(move + n) % n]
  if (next) void choose(next.value, true)
}
</script>

<template>
  <div class="tabs" :class="{ compact }" role="tablist" :aria-label="label" @keydown="onKey">
    <button
      v-for="t in tabs"
      :id="`${idPrefix}-tab-${t.value}`"
      :key="t.value"
      ref="buttons"
      type="button"
      role="tab"
      class="tab"
      :aria-selected="modelValue === t.value"
      :aria-controls="`${idPrefix}-${t.value}`"
      :tabindex="modelValue === t.value ? 0 : -1"
      @click="choose(t.value)"
    >
      {{ t.label }}
    </button>
  </div>
</template>

<style scoped>
.tabs {
  display: flex;
  gap: var(--s-4);
  border-bottom: 1px solid var(--border);
}

.tab {
  position: relative;
  height: 40px;
  padding: 0 var(--s-14);
  border: 0;
  background: none;
  color: var(--text-2);
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: color 120ms ease;
}

/* In a side panel the tabs share its width, closer together. */
.tabs.compact {
  gap: 0;
}

.compact .tab {
  flex: 1 1 auto;
  padding: 0 var(--s-6);
}

.tab:hover {
  color: var(--text);
}

.tab[aria-selected='true'] {
  color: var(--text);
  font-weight: 600;
}

/* The accent marks the chosen tab: interaction, never data. */
.tab[aria-selected='true']::after {
  content: '';
  position: absolute;
  inset: auto 0 -1px;
  height: 2px;
  background: var(--accent);
}

@media (prefers-reduced-motion: reduce) {
  .tab {
    transition: none;
  }
}
</style>
