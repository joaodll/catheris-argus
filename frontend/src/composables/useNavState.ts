/**
 * The sidebar's per-browser conveniences: which modules are open, and whether it is the icon
 * rail. Kept in localStorage, which can be missing or throw (private windows, blocked storage):
 * the menu then works with its defaults.
 */
import { ref, watch } from 'vue'

const KEY = 'argus.nav'

type Saved = { open: string[]; rail: boolean }

function load(): Saved {
  try {
    const raw = localStorage.getItem(KEY)
    const value = raw ? (JSON.parse(raw) as Partial<Saved>) : {}
    return { open: Array.isArray(value.open) ? value.open.filter((m) => typeof m === 'string') : [], rail: value.rail === true }
  } catch {
    return { open: [], rail: false }
  }
}

const saved = load()
export const openModules = ref<Set<string>>(new Set(saved.open))
export const railMode = ref(saved.rail)

watch([openModules, railMode], () => {
  try {
    localStorage.setItem(KEY, JSON.stringify({ open: [...openModules.value], rail: railMode.value }))
  } catch {
    // Storage unavailable: the state lasts for this page only.
  }
})

export function toggleModule(id: string): void {
  const next = new Set(openModules.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  openModules.value = next
}

/** The current page's module opens; a module the user opened stays open. */
export function openModule(id: string): void {
  if (!openModules.value.has(id)) openModules.value = new Set(openModules.value).add(id)
}
