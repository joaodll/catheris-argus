<script setup lang="ts">
/**
 * Summary | List under an Investigate screen's title (owner's decision 2026-11-05; spec in the
 * palace, frontend/0064ccbd). Underline tabs, a level above the panel's List | By check toggle.
 * The view owns the panels (ids `<idPrefix>-summary` and `<idPrefix>-list`) and the URL; this
 * only reports a choice. Arrow keys move and choose, Home and End jump; only the chosen tab is
 * in the tab order.
 */
import { nextTick, ref } from 'vue'
import { TABS, type Tab } from './summaryTab'

const props = defineProps<{ modelValue: Tab; label: string; idPrefix: string }>()
const emit = defineEmits<{ 'update:modelValue': [tab: Tab] }>()

const LABEL: Record<Tab, string> = { summary: 'Summary', list: 'List' }
const buttons = ref<HTMLButtonElement[]>([])

async function choose(tab: Tab, focus = false): Promise<void> {
  if (tab !== props.modelValue) emit('update:modelValue', tab)
  if (focus) {
    await nextTick()
    buttons.value[TABS.indexOf(tab)]?.focus()
  }
}

function onKey(event: KeyboardEvent): void {
  const at = TABS.indexOf(props.modelValue)
  const moves: Record<string, number> = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: TABS.length - 1 }
  const move = moves[event.key]
  if (move === undefined) return
  event.preventDefault()
  const next = TABS[(move + TABS.length) % TABS.length]
  if (next) void choose(next, true)
}
</script>

<template>
  <div class="tabs" role="tablist" :aria-label="label" @keydown="onKey">
    <button
      v-for="t in TABS"
      :id="`${idPrefix}-tab-${t}`"
      :key="t"
      ref="buttons"
      type="button"
      role="tab"
      class="tab"
      :aria-selected="modelValue === t"
      :aria-controls="`${idPrefix}-${t}`"
      :tabindex="modelValue === t ? 0 : -1"
      @click="choose(t)"
    >
      {{ LABEL[t] }}
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
