<script setup lang="ts">
/** Copies a value (a resource uid) and says "Copied" in a polite live region for 2 s. */
import { onBeforeUnmount, ref } from 'vue'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ value: string; label: string }>()
const copied = ref(false)
let timer: number | undefined

async function copy(): Promise<void> {
  try {
    await navigator.clipboard.writeText(props.value)
  } catch {
    return // no clipboard access (an insecure context): the value stays selectable
  }
  copied.value = true
  window.clearTimeout(timer)
  timer = window.setTimeout(() => (copied.value = false), 2000)
}

onBeforeUnmount(() => window.clearTimeout(timer))
</script>

<template>
  <span class="copy">
    <button type="button" class="icon-btn" :aria-label="props.label" :title="props.label" @click="copy">
      <AppIcon :name="copied ? 'check' : 'copy'" :size="16" />
    </button>
    <span class="cap" aria-live="polite">{{ copied ? 'Copied' : '' }}</span>
  </span>
</template>

<style scoped>
.copy {
  display: inline-flex;
  align-items: center;
  gap: var(--s-4);
  vertical-align: middle;
}
</style>
