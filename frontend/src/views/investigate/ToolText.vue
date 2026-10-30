<script setup lang="ts">
/** Tool-written text with its bold, italic and code marks (toolText.ts), as elements only. */
import { computed } from 'vue'
import { toolText } from './toolText'

const props = defineProps<{ text: string }>()
const segments = computed(() => toolText(props.text))
</script>

<template>
  <p class="tool-text">
    <template v-for="(s, i) in segments" :key="i">
      <strong v-if="s.kind === 'strong'">{{ s.value }}</strong>
      <em v-else-if="s.kind === 'em'">{{ s.value }}</em>
      <code v-else-if="s.kind === 'code'" class="mono">{{ s.value }}</code>
      <template v-else>{{ s.value }}</template>
    </template>
  </p>
</template>

<style scoped>
.tool-text {
  margin: 0;
  max-width: 80ch;
  white-space: pre-line;
  overflow-wrap: anywhere;
}

strong {
  font-weight: 600;
}

code {
  font-size: 0.92em;
  padding: 0 4px;
  border-radius: 4px;
  background: var(--surface-raised);
}
</style>
