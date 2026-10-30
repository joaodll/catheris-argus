<script setup lang="ts">
/**
 * A filter that picks several values (design-system.md, Multi-select): a select-like trigger
 * and a panel holding a listbox of checkboxes, searchable when long. Each toggle applies at
 * once; nothing chosen means no filter ("All").
 */
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import AppIcon from './AppIcon.vue'
import ToolChip from './ToolChip.vue'

export interface MultiOption {
  value: string
  label: string
  mono?: boolean
  tool?: string // a check shows its tool chip
  note?: string // a short aside after the label ("not covered")
}

const props = withDefaults(
  defineProps<{
    id: string
    label: string
    options: MultiOption[]
    modelValue: string[]
    status?: 'ready' | 'loading' | 'error'
  }>(),
  { status: 'ready' },
)
const emit = defineEmits<{ 'update:modelValue': [string[]] }>()

const SEARCH_FROM = 8 // more options than this: a search row

const root = ref<HTMLElement | null>(null)
const trigger = ref<HTMLButtonElement | null>(null)
const searchInput = ref<HTMLInputElement | null>(null)
const listbox = ref<HTMLElement | null>(null)
const open = ref(false)
const above = ref(false)
const filter = ref('')
const active = ref(0)

const chosen = computed(() => new Set(props.modelValue))
const disabled = computed(() => props.status !== 'ready' || props.options.length === 0)
const searchable = computed(() => props.options.length > SEARCH_FROM)
const shown = computed(() => {
  const term = filter.value.trim().toLowerCase()
  return term ? props.options.filter((o) => o.label.toLowerCase().includes(term)) : props.options
})
const labels = computed(() => props.options.filter((o) => chosen.value.has(o.value)).map((o) => o.label))
const summary = computed(() => {
  if (props.status === 'loading') return 'Loading…'
  if (props.status === 'error') return 'Unavailable'
  if (props.options.length === 0) return 'None in the data'
  return labels.value[0] ?? 'All'
})
const extra = computed(() => Math.max(0, labels.value.length - 1))
const optionId = (index: number): string => `${props.id}-opt-${index}`
const activeId = computed(() => (shown.value.length ? optionId(active.value) : undefined))

function toggleValue(value: string): void {
  const next = chosen.value.has(value) ? props.modelValue.filter((v) => v !== value) : [...props.modelValue, value]
  emit('update:modelValue', next)
}

async function openPanel(): Promise<void> {
  if (disabled.value || open.value) return
  const box = trigger.value?.getBoundingClientRect()
  above.value = Boolean(box && box.bottom + 340 > window.innerHeight && box.top > 340)
  filter.value = ''
  active.value = 0
  open.value = true
  await nextTick()
  ;(searchable.value ? searchInput.value : listbox.value)?.focus()
}

function close(refocus: boolean): void {
  open.value = false
  if (refocus) trigger.value?.focus()
}

function onTrigger(): void {
  if (open.value) close(false)
  else void openPanel()
}

function move(to: number): void {
  if (!shown.value.length) return
  active.value = Math.min(Math.max(to, 0), shown.value.length - 1)
  void nextTick(() => document.getElementById(optionId(active.value))?.scrollIntoView?.({ block: 'nearest' }))
}

function onKey(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    event.preventDefault()
    close(true)
    return
  }
  // The search field and the listbox move and toggle; the footer's Clear is a plain button.
  const inSearch = event.target === searchInput.value
  if (!inSearch && event.target !== listbox.value) return
  switch (event.key) {
    case 'ArrowDown':
      move(active.value + 1)
      break
    case 'ArrowUp':
      move(active.value - 1)
      break
    case 'Home':
      if (inSearch) return
      move(0)
      break
    case 'End':
      if (inSearch) return
      move(shown.value.length - 1)
      break
    case ' ':
      if (inSearch) return
    // falls through: Space toggles like Enter outside the search field
    case 'Enter': {
      const option = shown.value[active.value]
      if (option) toggleValue(option.value)
      break
    }
    default:
      return
  }
  event.preventDefault()
}

watch(filter, () => (active.value = 0))

// Tab out of the panel (past Clear) closes it.
function onFocusOut(event: FocusEvent): void {
  if (!root.value?.contains(event.relatedTarget as Node | null)) close(false)
}

function onOutside(event: PointerEvent): void {
  if (root.value && !root.value.contains(event.target as Node)) close(false)
}
watch(open, (isOpen) => {
  if (isOpen) document.addEventListener('pointerdown', onOutside)
  else document.removeEventListener('pointerdown', onOutside)
})
onBeforeUnmount(() => document.removeEventListener('pointerdown', onOutside))
</script>

<template>
  <div ref="root" class="field ms">
    <span :id="`${id}-lbl`" class="lbl">{{ label }}</span>
    <button
      :id="id"
      ref="trigger"
      type="button"
      class="select ms-trigger"
      :class="{ open, idle: !labels.length || disabled }"
      aria-haspopup="listbox"
      :aria-expanded="open"
      :aria-controls="`${id}-list`"
      :aria-labelledby="`${id}-lbl ${id}`"
      :aria-disabled="disabled || undefined"
      :title="labels.length ? labels.join(', ') : undefined"
      @click="onTrigger"
      @keydown.down.prevent="openPanel"
    >
      <span class="ms-text" :class="{ mono: labels.length && options.find((o) => o.label === labels[0])?.mono }">{{ summary }}</span>
      <span v-if="extra && !disabled" class="chip ms-more">+{{ extra }}</span>
      <AppIcon name="chevron" :size="16" :stroke="2" class="ms-chev" />
    </button>
    <div v-if="open" class="ms-panel" :class="{ above }" @keydown="onKey" @focusout="onFocusOut">
      <div v-if="searchable" class="ms-search">
        <AppIcon name="search" :size="16" class="ms-search-icon" />
        <input
          ref="searchInput"
          v-model="filter"
          class="input"
          type="search"
          :placeholder="`Filter ${label.toLowerCase()}`"
          :aria-label="`Filter ${label.toLowerCase()}`"
          :aria-controls="`${id}-list`"
          :aria-activedescendant="activeId"
          autocomplete="off"
        >
      </div>
      <ul
        :id="`${id}-list`"
        ref="listbox"
        class="ms-list"
        role="listbox"
        aria-multiselectable="true"
        :aria-labelledby="`${id}-lbl`"
        :aria-activedescendant="searchable ? undefined : activeId"
        :tabindex="searchable ? -1 : 0"
      >
        <li
          v-for="(o, i) in shown"
          :id="optionId(i)"
          :key="o.value"
          role="option"
          class="ms-option"
          :class="{ active: i === active }"
          :aria-selected="chosen.has(o.value)"
          @mousedown.prevent
          @mousemove="active = i"
          @click="toggleValue(o.value)"
        >
          <span class="ms-box" aria-hidden="true"><AppIcon v-if="chosen.has(o.value)" name="check" :size="14" :stroke="3" /></span>
          <span class="ms-label" :class="{ mono: o.mono }">{{ o.label }}</span>
          <ToolChip v-if="o.tool" :tool="o.tool" class="ms-tool" />
          <span v-if="o.note" class="cap ms-note">{{ o.note }}</span>
        </li>
      </ul>
      <p v-if="!shown.length" class="cap ms-none">No match</p>
      <div v-if="modelValue.length" class="ms-foot">
        <span class="cap">{{ modelValue.length }} selected</span>
        <button type="button" class="btn btn-ghost btn-sm" @click="emit('update:modelValue', [])">Clear</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ms {
  position: relative;
  width: auto;
}

.ms-trigger {
  display: flex;
  align-items: center;
  gap: var(--s-6);
  min-width: 160px;
  max-width: 240px;
  text-align: left;
  cursor: pointer;
}

.ms-trigger.idle .ms-text {
  color: var(--text-2);
}

.ms-trigger[aria-disabled='true'] {
  border-color: var(--border);
  cursor: default;
}

.ms-trigger[aria-disabled='true'] .ms-text {
  color: var(--text-3);
}

.ms-trigger.open {
  border-color: var(--accent);
}

.ms-text {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ms-text.mono {
  font-size: 12px;
}

.ms-more {
  background: var(--surface-raised);
  color: var(--text-2);
}

.ms-chev {
  flex: none;
  color: var(--text-3);
  transform: rotate(90deg);
}

.ms-trigger.open .ms-chev {
  transform: rotate(-90deg);
}

.ms-panel {
  position: absolute;
  top: calc(100% + var(--s-4));
  left: 0;
  z-index: 20;
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  min-width: 100%;
  width: max-content;
  max-width: min(320px, calc(100vw - 32px));
  max-height: 320px;
  padding: var(--s-6);
  background: var(--surface-raised);
  border: 1px solid var(--border-strong);
  border-radius: var(--r-tile);
  box-shadow: var(--shadow-sheet);
}

.ms-panel.above {
  top: auto;
  bottom: calc(100% + var(--s-4));
}

.ms-search {
  position: relative;
  flex: none;
}

.ms-search .input {
  height: var(--control-h-compact);
  padding-left: 32px;
}

.ms-search-icon {
  position: absolute;
  top: 50%;
  left: 10px;
  transform: translateY(-50%);
  color: var(--text-3);
  pointer-events: none;
}

.ms-list {
  flex: 1 1 auto;
  min-height: 0;
  margin: 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
  border-radius: 6px;
}

.ms-option {
  display: flex;
  align-items: center;
  gap: var(--s-10);
  min-height: 32px;
  padding: 0 var(--s-8);
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
}

.ms-option.active,
.ms-option:hover {
  background: var(--surface-active);
}

.ms-box {
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  border: 1px solid var(--border-control);
  border-radius: 4px;
  background: var(--surface-sunken);
}

.ms-option[aria-selected='true'] .ms-box {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--on-accent);
}

.ms-label {
  flex: 1 1 auto;
  min-width: 0;
  overflow-wrap: anywhere;
}

.ms-label.mono {
  font-size: 12px;
}

.ms-tool,
.ms-note {
  flex: none;
}

.ms-none {
  margin: 0;
  padding: var(--s-8);
  text-align: center;
}

.ms-foot {
  flex: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-8);
  padding: var(--s-4) var(--s-4) 0 var(--s-8);
  border-top: 1px solid var(--border);
}

.ms-list:focus-visible {
  outline-offset: 0;
}

@media (max-width: 900px) {
  .ms-option {
    min-height: 44px;
  }
}

@media (prefers-reduced-motion: no-preference) {
  .ms-chev {
    transition: transform var(--ease);
  }
}
</style>
