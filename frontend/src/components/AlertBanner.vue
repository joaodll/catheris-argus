<script setup lang="ts">
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'
import type { IconName } from './icons'

const props = withDefaults(defineProps<{ kind?: 'info' | 'warn' | 'fail' | 'ok' }>(), { kind: 'info' })
const ICON: Record<string, IconName> = { info: 'info', warn: 'warning', fail: 'cross', ok: 'check' }
const icon = computed(() => ICON[props.kind] ?? 'info')
</script>

<template>
  <div class="banner" :class="`k-${props.kind}`" :role="props.kind === 'fail' ? 'alert' : 'status'">
    <AppIcon :name="icon" :size="16" :stroke="2.2" class="icon" />
    <div class="body"><slot /></div>
    <div v-if="$slots.action" class="action"><slot name="action" /></div>
  </div>
</template>

<style scoped>
.banner {
  display: flex;
  gap: var(--s-10);
  align-items: flex-start;
  padding: var(--s-12) var(--s-14);
  border-radius: var(--r-tile);
  border: 1px solid var(--border-control);
  font-size: 13px;
  line-height: 1.45;
  color: var(--text);
}

.icon {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--text-2);
}

.body {
  flex: 1;
  min-width: 0;
}

.action {
  flex-shrink: 0;
}

.k-warn {
  border-color: color-mix(in srgb, var(--status-warn) 55%, transparent);
  background: color-mix(in srgb, var(--status-warn) 8%, transparent);
}

.k-warn .icon {
  color: var(--status-warn);
}

.k-fail {
  border-color: color-mix(in srgb, var(--status-fail) 60%, transparent);
  background: color-mix(in srgb, var(--status-fail) 8%, transparent);
}

.k-fail .icon {
  color: var(--status-fail);
}

.k-ok {
  border-color: color-mix(in srgb, var(--status-ok) 55%, transparent);
  background: color-mix(in srgb, var(--status-ok) 8%, transparent);
}

.k-ok .icon {
  color: var(--status-ok);
}
</style>
