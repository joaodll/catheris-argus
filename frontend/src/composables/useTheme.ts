/**
 * The theme (design-system.md, "Light theme" and Shell → user block; 2026-10-14): Light, Dark or
 * System, as in CatherIs Platform. The choice is kept per browser; System, the default, follows
 * the operating system and changes with it. The resolved theme is stamped on <html> as
 * data-theme, which tokens.css reads. main.ts imports this module first, so the page is stamped
 * before the app mounts.
 */
import { computed, readonly, ref, watch } from 'vue'

export type ThemeChoice = 'light' | 'dark' | 'system'

const KEY = 'argus.theme'
const ORDER: ThemeChoice[] = ['light', 'dark', 'system']

function read(): ThemeChoice {
  try {
    const stored = window.localStorage.getItem(KEY)
    return stored === 'light' || stored === 'dark' ? stored : 'system'
  } catch {
    return 'system' // storage blocked: follow the operating system
  }
}

const choice = ref<ThemeChoice>(read())
const media = typeof window !== 'undefined' ? window.matchMedia?.('(prefers-color-scheme: light)') : undefined
const systemLight = ref(media?.matches ?? false)
media?.addEventListener?.('change', (event) => {
  systemLight.value = event.matches
})

/** The theme on screen: the choice, or what the operating system prefers for System. */
export const resolvedTheme = computed<'light' | 'dark'>(() => (choice.value === 'system' ? (systemLight.value ? 'light' : 'dark') : choice.value))
export const themeChoice = readonly(choice)

function stamp(theme: 'light' | 'dark'): void {
  if (typeof document !== 'undefined') document.documentElement.dataset.theme = theme
}
stamp(resolvedTheme.value)
watch(resolvedTheme, stamp)

/** The shell's button: Light → Dark → System → Light. */
export function cycleTheme(): void {
  choice.value = ORDER[(ORDER.indexOf(choice.value) + 1) % ORDER.length]!
  try {
    window.localStorage.setItem(KEY, choice.value)
  } catch {
    // Storage blocked: the choice lasts for this page only.
  }
}

const LABEL: Record<ThemeChoice, string> = { light: 'Light', dark: 'Dark', system: 'System' }
export const themeLabel = computed(() => `Theme: ${LABEL[choice.value]} — click to change`)
