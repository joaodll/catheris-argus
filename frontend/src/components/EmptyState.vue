<script setup lang="ts">
import AppIcon from './AppIcon.vue'
import type { IconName } from './icons'

defineProps<{ title: string; text?: string; icon?: IconName }>()
</script>

<template>
  <div class="empty">
    <AppIcon :name="icon ?? 'stack'" :size="32" :stroke="1.6" class="icon" />
    <h3 class="h2">{{ title }}</h3>
    <p v-if="text" class="cap">{{ text }}</p>
    <slot />
  </div>
</template>

<style scoped>
.empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--s-10);
  padding: var(--s-32) var(--s-24);
  text-align: center;
}

.icon {
  color: var(--text-3);
}

p {
  margin: 0;
  max-width: 420px;
}
</style>
