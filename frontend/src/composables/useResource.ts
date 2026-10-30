import { onScopeDispose, ref, shallowRef, watch, type Ref, type WatchSource } from 'vue'
import { ApiError } from '@/api/client'

/**
 * Loads server data with loading and error state. Reloads when any watched source changes and,
 * optionally, on an interval while the page is visible. A late answer to an older request never
 * overwrites a newer one.
 */
export function useResource<T>(
  load: () => Promise<T>,
  options: { watch?: WatchSource[]; refreshMs?: number } = {},
): { data: Ref<T | null>; error: Ref<string | null>; loading: Ref<boolean>; reload: () => Promise<void> } {
  const data = shallowRef<T | null>(null) as Ref<T | null>
  const error = ref<string | null>(null)
  const loading = ref(false)
  let generation = 0

  async function reload(): Promise<void> {
    const mine = ++generation
    loading.value = true
    try {
      const value = await load()
      if (mine !== generation) return
      data.value = value
      error.value = null
    } catch (err) {
      if (mine !== generation) return
      error.value = err instanceof ApiError ? err.message : 'Something went wrong while loading.'
    } finally {
      if (mine === generation) loading.value = false
    }
  }

  if (options.watch?.length) watch(options.watch, () => void reload())
  void reload()

  if (options.refreshMs) {
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void reload()
    }, options.refreshMs)
    onScopeDispose(() => window.clearInterval(timer))
  }
  return { data, error, loading, reload }
}
