import { onBeforeUnmount, onMounted, type Ref } from 'vue'
import type { Router } from 'vue-router'

/**
 * Unsaved-changes guard for the whole app. A form registers its `dirty` flag while mounted;
 * leaving the page (a route change, or closing the tab) while any flag is true asks once, with
 * the browser's own confirm() as in CatherIs Platform (ADR-0028, fifth amendment), however many
 * forms are dirty.
 */
const sources = new Set<Ref<boolean>>()

export const LEAVE_QUESTION = "Discard unsaved changes? You are leaving this page, and changes you haven't saved are lost."

function anyDirty(): boolean {
  return [...sources].some((dirty) => dirty.value)
}

/** Installed once, from main.ts. */
export function installLeaveGuard(router: Router): void {
  router.beforeEach((to, from) => {
    // An expired session goes to sign-in regardless: a save could not succeed anyway.
    if (to.path === from.path || to.name === 'sign-in' || !anyDirty()) return true
    return window.confirm(LEAVE_QUESTION)
  })
  window.addEventListener('beforeunload', (event) => {
    if (anyDirty()) event.preventDefault()
  })
}

/** Registers a form's unsaved-changes flag while the form is mounted. */
export function useDirtyGuard(dirty: Ref<boolean>): void {
  onMounted(() => sources.add(dirty))
  onBeforeUnmount(() => sources.delete(dirty))
}
