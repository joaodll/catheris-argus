<script setup lang="ts">
/**
 * The Map's page tabs, Map | Attack paths (owner, 2026-11-15, palace decisions/97db351b), under the
 * page title as Summary | List sits on the other Investigate screens. Each tab is its own route
 * (/investigate/map and /investigate/map/attack-paths), so these are links in a nav, not ARIA
 * tabs: the look of UnderlineTabs, the semantics of navigation.
 */
defineProps<{ current: 'map' | 'attack-paths' }>()
const TABS = [
  { value: 'map', label: 'Map', to: { name: 'map' } },
  { value: 'attack-paths', label: 'Attack paths', to: { name: 'attack-paths' } },
] as const
</script>

<template>
  <nav class="tabs" aria-label="Map views">
    <RouterLink v-for="t in TABS" :key="t.value" :to="t.to" class="tab" :aria-current="current === t.value ? 'page' : undefined">{{ t.label }}</RouterLink>
  </nav>
</template>

<style scoped>
.tabs {
  display: flex;
  gap: var(--s-4);
  margin-bottom: var(--s-16);
  border-bottom: 1px solid var(--border);
}

.tab {
  position: relative;
  display: inline-flex;
  align-items: center;
  height: 40px;
  padding: 0 var(--s-14);
  color: var(--text-2);
  font-size: 13px;
  font-weight: 500;
  text-decoration: none;
  transition: color 120ms ease;
}

.tab:hover {
  color: var(--text);
}

.tab[aria-current='page'] {
  color: var(--text);
  font-weight: 600;
}

/* The accent marks the chosen tab: interaction, never data. */
.tab[aria-current='page']::after {
  content: '';
  position: absolute;
  inset: auto 0 -1px;
  height: 2px;
  background: var(--accent);
}

@media (prefers-reduced-motion: reduce) {
  .tab {
    transition: none;
  }
}
</style>
