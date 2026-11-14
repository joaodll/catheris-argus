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
    <template v-else-if="props.name === 'report'"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5M9 13h6M9 17h6" /></template>
    <template v-else-if="props.name === 'download'"><path d="M12 4v11M7 10l5 5 5-5M5 20h14" /></template>
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
    <template v-else-if="props.name === 'flag'"><path d="M5 21V4" /><path d="M5 4h11l-2 4 2 4H5" /></template>
    <template v-else-if="props.name === 'calendar'"><rect x="3" y="5" width="18" height="16" rx="2" /><path d="M8 3v4M16 3v4M3 10h18" /></template>
    <template v-else-if="props.name === 'checklist'"><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4V3h6v1" /><path d="M8 10l1.2 1.2L11.5 9M13.5 10.5H16M8 15.5l1.2 1.2 2.3-2.2M13.5 16H16" /></template>
    <template v-else-if="props.name === 'copy'"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h8" /></template>
    <template v-else-if="props.name === 'dot'"><circle cx="12" cy="12" r="4" fill="currentColor" /></template>
    <template v-else-if="props.name === 'plug'"><path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4" /></template>
    <template v-else-if="props.name === 'chip'"><rect x="7" y="7" width="10" height="10" rx="2" /><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" /></template>
    <template v-else-if="props.name === 'users'"><circle cx="9" cy="8" r="3.5" /><path d="M3 20a6 6 0 0 1 12 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5a6 6 0 0 1 3 5.5" /></template>
    <template v-else-if="props.name === 'key'"><circle cx="8" cy="12" r="4" /><path d="M12 12h9M18 12v3M21 12v2" /></template>
    <template v-else-if="props.name === 'external'"><path d="M14 4h6v6M20 4l-9 9" /><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></template>
    <template v-else-if="props.name === 'sun'"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></template>
    <template v-else-if="props.name === 'moon'"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></template>
    <template v-else-if="props.name === 'monitor'"><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></template>
    <template v-else-if="props.name === 'graph'"><circle cx="5" cy="16" r="2.5" /><circle cx="12" cy="7" r="2.5" /><circle cx="19" cy="16" r="2.5" /><path d="M6.4 13.9l4.2-4.8M13.4 9.1l4.2 4.8" /></template>
    <template v-else-if="props.name === 'expand'"><path d="M13 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7" /><path d="M15 3h6v6M21 3l-8 8" /></template>
    <template v-else-if="props.name === 'minus'"><path d="M5 12h14" /></template>
    <template v-else-if="props.name === 'fit'"><path d="M4 9V5a1 1 0 0 1 1-1h4M15 4h4a1 1 0 0 1 1 1v4M20 15v4a1 1 0 0 1-1 1h-4M9 20H5a1 1 0 0 1-1-1v-4" /></template>
    <template v-else-if="props.name === 'layers'"><path d="M12 3L3 8l9 5 9-5z" /><path d="M3 13l9 5 9-5" /></template>
    <template v-else-if="props.name === 'globe'"><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z" /></template>
    <template v-else-if="props.name === 'server'"><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M7 7.5h.01M7 16.5h.01" /></template>
    <template v-else-if="props.name === 'lambda'"><path d="M6 4h3l7 16h3M11.2 9.2L6 20" /></template>
    <template v-else-if="props.name === 'container'"><rect x="3" y="6" width="18" height="12" rx="1.5" /><path d="M8 9.5v5M12 9.5v5M16 9.5v5" /></template>
    <template v-else-if="props.name === 'helm'"><circle cx="12" cy="12" r="5.5" /><circle cx="12" cy="12" r="1.3" /><path d="M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4M5.3 5.3l2.8 2.8M15.9 15.9l2.8 2.8M5.3 18.7l2.8-2.8M15.9 8.1l2.8-2.8" /></template>
    <template v-else-if="props.name === 'registry'"><rect x="4" y="13" width="7" height="7" rx="1" /><rect x="13" y="13" width="7" height="7" rx="1" /><rect x="8.5" y="4" width="7" height="7" rx="1" /></template>
    <template v-else-if="props.name === 'bucket'"><ellipse cx="12" cy="6" rx="8" ry="2.5" /><path d="M4 6l2 13c.2 1.1 2.8 2 6 2s5.8-.9 6-2l2-13" /></template>
    <template v-else-if="props.name === 'disk'"><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6" /></template>
    <template v-else-if="props.name === 'database'"><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" /></template>
    <template v-else-if="props.name === 'table'"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 9.5h18M3 14.5h18M9 4v16M15 4v16" /></template>
    <template v-else-if="props.name === 'vpc'"><path d="M7 18a4 4 0 0 1-.6-7.95A5.5 5.5 0 0 1 17 8.6a4.7 4.7 0 0 1 .5 9.4z" /></template>
    <template v-else-if="props.name === 'subnet'"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M12 4v16M7.5 12h.01M16.5 12h.01" /></template>
    <template v-else-if="props.name === 'firewall'"><rect x="3" y="4" width="18" height="16" rx="1.5" /><path d="M3 9.3h18M3 14.7h18M9 4v5.3M15 4v5.3M6 9.3v5.4M12 9.3v5.4M18 9.3v5.4M9 14.7V20M15 14.7V20" /></template>
    <template v-else-if="props.name === 'balancer'"><circle cx="5" cy="12" r="2" /><path d="M7 12h13M11 12l3.5-6H20M11 12l3.5 6H20" /></template>
    <template v-else-if="props.name === 'target'"><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1" fill="currentColor" /></template>
    <template v-else-if="props.name === 'gateway'"><path d="M5 4v16M19 4v16M8 12h8M13 9l3 3-3 3" /></template>
    <template v-else-if="props.name === 'cdn'"><circle cx="12" cy="12" r="9" /><path d="M3.6 9h16.8M3.6 15h16.8M12 3v18" /></template>
    <template v-else-if="props.name === 'dns'"><path d="M12 3v18" /><path d="M12 5h6l2 2.5-2 2.5h-6zM12 12H6l-2 2.5L6 17h6z" /></template>
    <template v-else-if="props.name === 'role'"><rect x="5" y="3" width="14" height="18" rx="2" /><circle cx="12" cy="10.5" r="2.5" /><path d="M8.5 17.5a3.5 3.5 0 0 1 7 0M10 3v2h4V3" /></template>
    <template v-else-if="props.name === 'user'"><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></template>
    <template v-else-if="props.name === 'policy'"><path d="M6 3h9l4 4v14H6z" /><path d="M15 3v4h4M9 14l2 2 4-4" /></template>
    <template v-else-if="props.name === 'kms'"><path d="M12 2.5l8.2 4.75v9.5L12 21.5l-8.2-4.75v-9.5z" /><circle cx="9.5" cy="12" r="2" /><path d="M11.5 12h5M15 12v2" /></template>
    <template v-else-if="props.name === 'lock'"><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></template>
    <template v-else-if="props.name === 'filter'"><path d="M3 5h18l-7 8v6l-4 2v-8z" /></template>
    <template v-else-if="props.name === 'certificate'"><rect x="3" y="4" width="18" height="13" rx="2" /><path d="M7 9h6M7 12.5h4" /><circle cx="16.5" cy="13" r="2.5" /><path d="M15 15.2V21l1.5-1.2L18 21v-5.8" /></template>
    <template v-else-if="props.name === 'queue'"><rect x="3" y="6" width="4" height="12" rx="1" /><rect x="9" y="6" width="4" height="12" rx="1" /><path d="M16 12h5M19 9.5l2.5 2.5-2.5 2.5" /></template>
    <template v-else-if="props.name === 'topic'"><circle cx="6" cy="18" r="1.5" fill="currentColor" /><path d="M5 11a8 8 0 0 1 8 8M5 5a14 14 0 0 1 14 14" /></template>
    <template v-else-if="props.name === 'event'"><path d="M13 2L5 13.5h6L10 22l9-12h-6z" /></template>
    <template v-else-if="props.name === 'flow'"><rect x="3" y="9.5" width="5" height="5" rx="1" /><rect x="16" y="3.5" width="5" height="5" rx="1" /><rect x="16" y="15.5" width="5" height="5" rx="1" /><path d="M8 12h4M12 12V6h4M12 12v6h4" /></template>
    <template v-else-if="props.name === 'stream'"><path d="M3 9c3-3 6-3 9 0s6 3 9 0M3 16c3-3 6-3 9 0s6 3 9 0" /></template>
    <template v-else-if="props.name === 'log'"><path d="M4 6h8M4 10.5h16M4 15h16M4 19.5h12" /></template>
    <template v-else-if="props.name === 'nodes'"><circle cx="12" cy="5" r="2.2" /><circle cx="5" cy="19" r="2.2" /><circle cx="19" cy="19" r="2.2" /><path d="M12 7.2v5M12 12.2l-5.7 5M12 12.2l5.7 5" /></template>
    <template v-else-if="props.name === 'chart'"><path d="M4 20V10M10 20V4M16 20v-7M21 20H3" /></template>
    <template v-else-if="props.name === 'sliders'"><path d="M4 7h10M18 7h2M4 17h2M10 17h10" /><circle cx="16" cy="7" r="2" /><circle cx="8" cy="17" r="2" /></template>
    <template v-else-if="props.name === 'cube'"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" /><path d="M4 7.5l8 4.5 8-4.5M12 12v9" /></template>
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
