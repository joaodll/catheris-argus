<script setup lang="ts">
/**
 * Reloads a page's data on demand: the page header's action (design-system.md, Page header).
 * Busy only while its own reload runs, so the background refresh of a queue does not make it
 * flicker. It stays focusable while busy (aria-disabled, not disabled), so a keyboard user who
 * pressed it keeps their place.
 */
import { ref } from 'vue'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ reload: () => Promise<unknown> }>()
const busy = ref(false)

async function refresh(): Promise<void> {
  if (busy.value) return
  busy.value = true
  try {
    await props.reload()
  } catch {
    // The page shows its own error banner for a list that did not load.
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <button type="button" class="btn btn-secondary btn-sm" :aria-disabled="busy" @click="refresh">
    <AppIcon v-if="busy" name="spinner" :size="16" :stroke="2.4" />Refresh
  </button>
</template>
