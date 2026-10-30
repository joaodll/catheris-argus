<script setup lang="ts">
/**
 * Find a resource (docs/ui/screens.md, E11, Toolbar): a combobox over the Resources search
 * (GET /resources?q=). Each option shows the name, the type and the connection; choosing one
 * emits its uid. The ARIA 1.2 combobox pattern: focus stays in the input, the arrow keys move
 * the active option, Enter chooses, Esc closes.
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'

const props = defineProps<{ connectionName: (id: number) => string }>()
const emit = defineEmits<{ choose: [uid: string] }>()

const LIMIT = 8
const id = 'map-find'
const term = ref('')
const options = ref<Schemas['ResourceRow'][]>([])
const open = ref(false)
const active = ref(-1)
const status = ref<'idle' | 'loading' | 'error'>('idle')
let typing: number | undefined
let generation = 0

async function search(q: string): Promise<void> {
  const mine = ++generation
  status.value = 'loading'
  try {
    const page = await unwrap(api.GET('/api/v1/resources', { params: { query: { q, limit: LIMIT } } }))
    if (mine !== generation) return
    options.value = page.items
    active.value = page.items.length ? 0 : -1
    status.value = 'idle'
  } catch {
    if (mine === generation) status.value = 'error'
  }
}

watch(term, (value) => {
  window.clearTimeout(typing)
  const q = value.trim()
  if (q.length < 2) {
    options.value = []
    open.value = false
    return
  }
  open.value = true
  typing = window.setTimeout(() => void search(q), 250)
})
onBeforeUnmount(() => window.clearTimeout(typing))

const optionId = (i: number) => `${id}-opt-${i}`
const message = computed(() => {
  if (status.value === 'error') return "The search didn't load. Keep typing to try again."
  if (status.value === 'loading' && options.value.length === 0) return 'Searching…'
  if (options.value.length === 0) return 'No resource matches.'
  return null
})

function choose(row: Schemas['ResourceRow']): void {
  emit('choose', row.resource_uid)
  term.value = ''
  open.value = false
}

function onKey(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    if (open.value) event.stopPropagation()
    open.value = false
    return
  }
  if (!open.value || options.value.length === 0) return
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault()
    const step = event.key === 'ArrowDown' ? 1 : -1
    active.value = (active.value + step + options.value.length) % options.value.length
  } else if (event.key === 'Enter' && active.value >= 0) {
    event.preventDefault()
    choose(options.value[active.value]!)
  }
}
</script>

<template>
  <div class="field find">
    <label class="lbl" :for="id">Find a resource</label>
    <input
      :id="id"
      v-model="term"
      class="input"
      type="search"
      role="combobox"
      autocomplete="off"
      placeholder="Search by name, id or ARN"
      aria-autocomplete="list"
      :aria-expanded="open"
      :aria-controls="`${id}-list`"
      :aria-activedescendant="open && active >= 0 ? optionId(active) : undefined"
      @keydown="onKey"
      @blur="open = false"
    >
    <div v-show="open" class="panel">
      <ul :id="`${id}-list`" role="listbox" aria-label="Resources">
        <li
          v-for="(row, i) in options"
          :id="optionId(i)"
          :key="row.id"
          role="option"
          :aria-selected="i === active"
          :class="{ active: i === active }"
          @mousedown.prevent="choose(row)"
          @mousemove="active = i"
        >
          <span class="name">{{ row.name ?? row.native_id }}</span>
          <span class="meta"><span class="mono">{{ row.type }}</span> · {{ props.connectionName(row.connection_id) }}</span>
        </li>
      </ul>
      <p v-if="message" class="cap msg" role="status">{{ message }}</p>
    </div>
  </div>
</template>

<style scoped>
.find {
  position: relative;
  min-width: 280px;
  flex: 1 1 320px;
}

.panel {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  z-index: 20;
  margin-top: var(--s-4);
  background: var(--surface-raised);
  border: 1px solid var(--border-strong);
  border-radius: var(--r-control);
  box-shadow: var(--shadow-sheet);
  overflow: hidden;
}

ul {
  margin: 0;
  padding: var(--s-4) 0;
  list-style: none;
  max-height: 320px;
  overflow-y: auto;
}

li {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: var(--s-6) var(--s-12);
  cursor: pointer;
}

li.active {
  background: var(--surface-active);
}

.name {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.meta {
  font-size: 12px;
  color: var(--text-2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.meta .mono {
  font-size: 12px;
}

.msg {
  margin: 0;
  padding: var(--s-8) var(--s-12);
}
</style>
