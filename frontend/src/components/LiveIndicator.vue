<script setup lang="ts">
/** "N runs in progress" in a page header (design-system.md, Live indicator). Shown only while
 * something runs: the parent passes 0 while loading or after a load error. */
defineProps<{ count: number }>()
</script>

<template>
  <span role="status" class="live-slot">
    <span v-if="count > 0" class="live">
      <span class="dot" aria-hidden="true"></span>
      <span><span class="mono">{{ count }}</span> {{ count === 1 ? 'run' : 'runs' }} in progress</span>
    </span>
  </span>
</template>

<style scoped>
.live-slot:empty {
  display: none;
}

.live {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  height: 24px;
  padding: 0 var(--s-10);
  border-radius: var(--r-chip);
  border: 1px solid color-mix(in srgb, var(--status-run) 40%, transparent);
  background: color-mix(in srgb, var(--status-run) 12%, transparent);
  color: var(--status-run);
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}

.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--status-run);
  animation: pulse 1.4s ease-in-out infinite;
}

@keyframes pulse {
  0%,
  100% {
    opacity: 1;
  }

  50% {
    opacity: 0.35;
  }
}

@media (prefers-reduced-motion: reduce) {
  .dot {
    animation: none;
  }
}
</style>
