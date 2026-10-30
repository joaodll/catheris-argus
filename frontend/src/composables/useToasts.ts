import { ref } from 'vue'

/** CatherIs Platform's typed toasts (design-system.md, Toast; ADR-0028, fifth amendment). */
export type ToastKind = 'success' | 'info' | 'warning' | 'error'

export interface Toast {
  id: number
  kind: ToastKind
  text: string
}

export const toasts = ref<Toast[]>([])
let next = 0

// How long each kind stays; hover or focus pauses it (ToastHost).
const STAYS: Record<ToastKind, number> = { success: 5000, info: 5000, warning: 8000, error: 8000 }
const timers = new Map<number, { left: number; started: number; handle: number | undefined }>()

export function dismiss(id: number): void {
  window.clearTimeout(timers.get(id)?.handle)
  timers.delete(id)
  toasts.value = toasts.value.filter((t) => t.id !== id)
}

function start(id: number): void {
  const timer = timers.get(id)
  if (!timer) return
  timer.started = Date.now()
  timer.handle = window.setTimeout(() => dismiss(id), timer.left)
}

export function pause(id: number): void {
  const timer = timers.get(id)
  if (!timer || timer.handle === undefined) return
  window.clearTimeout(timer.handle)
  timer.handle = undefined
  timer.left = Math.max(1000, timer.left - (Date.now() - timer.started))
}

export function resume(id: number): void {
  if (timers.get(id)?.handle === undefined) start(id)
}

/** A short message in the corner: a confirmation by default. */
export function toast(text: string, kind: ToastKind = 'success'): void {
  const id = ++next
  toasts.value = [...toasts.value, { id, kind, text }]
  timers.set(id, { left: STAYS[kind], started: Date.now(), handle: undefined })
  start(id)
}
