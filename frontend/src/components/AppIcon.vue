<script setup lang="ts">
/** The board's 24-grid stroke icons. Decorative: the text next to an icon carries the meaning. */
import type { IconName } from './icons'

const props = withDefaults(defineProps<{ name: IconName; size?: number; stroke?: number }>(), {
  size: 16,
  stroke: 1.8,
})

</script>

<template>
  <svg
    :width="props.size"
    :height="props.size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    :stroke-width="props.stroke"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
    :class="{ spin: props.name === 'spinner' }"
  >
    <template v-if="props.name === 'shield'"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" /><path d="M9 12l2 2 4-4" /></template>
    <template v-else-if="props.name === 'overview'"><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></template>
    <template v-else-if="props.name === 'admin'"><path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1" /><circle cx="15" cy="6" r="2" /><circle cx="9" cy="12" r="2" /><circle cx="17" cy="18" r="2" /></template>
    <template v-else-if="props.name === 'bug'"><rect x="8" y="7" width="8" height="13" rx="4" /><path d="M9.5 7a2.5 2.5 0 0 1 5 0M12 11v9M4 9l4 2M20 9l-4 2M3 14h5M16 14h5M4 20l4-3M20 20l-4-3" /></template>
    <template v-else-if="props.name === 'plus'"><path d="M12 5v14M5 12h14" /></template>
    <template v-else-if="props.name === 'check'"><path d="M5 12l5 5L20 7" /></template>
    <template v-else-if="props.name === 'cross'"><path d="M6 6l12 12M18 6L6 18" /></template>
    <template v-else-if="props.name === 'half'"><circle cx="12" cy="12" r="8" /><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor" /></template>
    <template v-else-if="props.name === 'clock'"><circle cx="12" cy="12" r="8" /><path d="M12 8v4l3 2" /></template>
    <template v-else-if="props.name === 'spinner'"><path d="M12 4a8 8 0 1 1-8 8" /></template>
    <template v-else-if="props.name === 'warning'"><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17h.01" /></template>
    <template v-else-if="props.name === 'info'"><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></template>
    <template v-else-if="props.name === 'eye'"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></template>
    <template v-else-if="props.name === 'eye-off'"><path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6C3.8 8.4 2 12 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></template>
    <template v-else-if="props.name === 'chevron'"><path d="M9 6l6 6-6 6" /></template>
    <template v-else-if="props.name === 'more'"><circle cx="5" cy="12" r="1.2" fill="currentColor" /><circle cx="12" cy="12" r="1.2" fill="currentColor" /><circle cx="19" cy="12" r="1.2" fill="currentColor" /></template>
    <template v-else-if="props.name === 'stack'"><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" /></template>
    <template v-else-if="props.name === 'blocked'"><circle cx="12" cy="12" r="8" /><path d="M6.5 17.5l11-11" /></template>
    <template v-else-if="props.name === 'signout'"><path d="M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10" /></template>
    <template v-else-if="props.name === 'scans'"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2M3 12h18" /></template>
    <template v-else-if="props.name === 'menu'"><path d="M4 6h16M4 12h16M4 18h16" /></template>
    <template v-else-if="props.name === 'search'"><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" /></template>
    <template v-else-if="props.name === 'panel'"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4v16" /></template>
    <template v-else-if="props.name === 'flag'"><path d="M5 21V4" /><path d="M5 4h11l-2 4 2 4H5" /></template>
    <template v-else-if="props.name === 'calendar'"><rect x="3" y="5" width="18" height="16" rx="2" /><path d="M8 3v4M16 3v4M3 10h18" /></template>
    <template v-else-if="props.name === 'checklist'"><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4V3h6v1" /><path d="M8 10l1.2 1.2L11.5 9M13.5 10.5H16M8 15.5l1.2 1.2 2.3-2.2M13.5 16H16" /></template>
    <template v-else-if="props.name === 'copy'"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h8" /></template>
    <template v-else-if="props.name === 'dot'"><circle cx="12" cy="12" r="4" fill="currentColor" /></template>
    <template v-else-if="props.name === 'graph'"><circle cx="5" cy="16" r="2.5" /><circle cx="12" cy="7" r="2.5" /><circle cx="19" cy="16" r="2.5" /><path d="M6.4 13.9l4.2-4.8M13.4 9.1l4.2 4.8" /></template>
    <template v-else-if="props.name === 'route'"><circle cx="5" cy="19" r="2" fill="currentColor" /><path d="M5 17V9a3 3 0 0 1 3-3h11" /><path d="M16 3l3 3-3 3" /></template>
    <template v-else-if="props.name === 'plug'"><path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4" /></template>
    <template v-else-if="props.name === 'chip'"><rect x="7" y="7" width="10" height="10" rx="2" /><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" /></template>
    <template v-else-if="props.name === 'database'"><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" /></template>
    <template v-else-if="props.name === 'nodes'"><circle cx="12" cy="5" r="2.2" /><circle cx="5" cy="19" r="2.2" /><circle cx="19" cy="19" r="2.2" /><path d="M12 7.2v5M12 12.2l-5.7 5M12 12.2l5.7 5" /></template>
    <template v-else-if="props.name === 'users'"><circle cx="9" cy="8" r="3.5" /><path d="M3 20a6 6 0 0 1 12 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5a6 6 0 0 1 3 5.5" /></template>
    <template v-else-if="props.name === 'key'"><circle cx="8" cy="12" r="4" /><path d="M12 12h9M18 12v3M21 12v2" /></template>
    <template v-else-if="props.name === 'cube'"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" /><path d="M4 7.5l8 4.5 8-4.5M12 12v9" /></template>
    <template v-else-if="props.name === 'external'"><path d="M14 4h6v6M20 4l-9 9" /><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></template>
    <template v-else-if="props.name === 'sun'"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></template>
    <template v-else-if="props.name === 'moon'"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></template>
    <template v-else-if="props.name === 'monitor'"><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></template>
    <template v-else-if="props.name === 'layers'"><path d="M12 3L3 8l9 5 9-5z" /><path d="M3 13l9 5 9-5" /></template>
    <template v-else-if="props.name === 'globe'"><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z" /></template>
    <template v-else-if="props.name === 'expand'"><path d="M13 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7" /><path d="M15 3h6v6M21 3l-8 8" /></template>
    <template v-else-if="props.name === 'minus'"><path d="M5 12h14" /></template>
    <template v-else-if="props.name === 'fit'"><path d="M4 9V5a1 1 0 0 1 1-1h4M15 4h4a1 1 0 0 1 1 1v4M20 15v4a1 1 0 0 1-1 1h-4M9 20H5a1 1 0 0 1-1-1v-4" /></template>
    <template v-else-if="props.name === 'reopen'"><path d="M4 12a8 8 0 0 1 14-5.3L20 9" /><path d="M20 4v5h-5" /><path d="M20 12a8 8 0 0 1-14 5.3L4 15" /></template>
  </svg>
</template>

<style scoped>
.spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
