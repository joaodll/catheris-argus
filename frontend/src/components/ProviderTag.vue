<script setup lang="ts">
/** Which cloud a row belongs to: a dot in the provider's fixed colour and its name
 * (design-system.md: provider colours are fixed on every screen; the name carries the meaning). */
import { providerName } from '@/providers'

defineProps<{ provider: string }>()
</script>

<template>
  <span class="provider"><span class="dot" :class="`dot-${provider}`" aria-hidden="true"></span>{{ providerName(provider) }}</span>
</template>

<style scoped>
.provider {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  font-size: 12px;
  font-weight: 600;
  color: var(--text-2);
  white-space: nowrap;
}

.dot {
  width: 8px;
  height: 8px;
}
</style>
