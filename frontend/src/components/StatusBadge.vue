<script setup lang="ts">
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'
import type { IconName } from './icons'

/** Icon + word + colour, always all three (design-system.md, Status badge). */
const props = defineProps<{ status: string; label?: string }>()

const LOOK: Record<string, { icon: IconName; text: string; tone: string }> = {
  complete: { icon: 'check', text: 'Complete', tone: 'ok' },
  set: { icon: 'check', text: 'Set', tone: 'ok' },
  partial: { icon: 'half', text: 'Partial', tone: 'warn' },
  failed: { icon: 'cross', text: 'Failed', tone: 'fail' },
  running: { icon: 'spinner', text: 'Running', tone: 'live' },
  claimed: { icon: 'spinner', text: 'Running', tone: 'live' },
  queued: { icon: 'clock', text: 'Queued', tone: 'idle' },
  disabled: { icon: 'blocked', text: 'Disabled', tone: 'idle' },
  warning: { icon: 'warning', text: 'Warning', tone: 'warn' },
  neutral: { icon: 'info', text: '', tone: 'idle' },
  // Finding states (Findings page). Open stays neutral: a state, not something running.
  open: { icon: 'dot', text: 'Open', tone: 'run' },
  reopened: { icon: 'reopen', text: 'Reopened', tone: 'warn' },
  resolved: { icon: 'check', text: 'Resolved', tone: 'ok' },
  accepted_risk: { icon: 'blocked', text: 'Accepted risk', tone: 'idle' },
  deleted: { icon: 'blocked', text: 'Deleted', tone: 'idle' },
  // A finding's reach: what Argus's internet rules say about the resource of a CloudFox public
  // endpoint or a Prowler exposure check (ADR-0035, sixth amendment). Argus's name, never the tool's.
  reach_confirmed: { icon: 'warning', text: 'Argus: Reachable', tone: 'warn' },
  reach_restricted: { icon: 'blocked', text: 'Argus: Restricted', tone: 'ok' },
  reach_unknown: { icon: 'eye-off', text: 'Argus: Unknown', tone: 'idle' },
  reach_not_covered: { icon: 'info', text: 'Argus: Not checked', tone: 'idle' },
  // A front door's reach on the Resource map (ADR-0035).
  conf_confirmed: { icon: 'check', text: 'Confirmed', tone: 'ok' },
  conf_supported: { icon: 'half', text: 'Supported', tone: 'idle' },
  conf_candidate: { icon: 'info', text: 'Candidate', tone: 'warn' },
  conf_unknown: { icon: 'eye-off', text: 'Unknown', tone: 'idle' },
  conf_blocked: { icon: 'blocked', text: 'Blocked', tone: 'idle' },
  door_open: { icon: 'warning', text: 'Reachable', tone: 'warn' },
  door_unknown: { icon: 'eye-off', text: 'Unknown', tone: 'idle' },
  door_restricted: { icon: 'blocked', text: 'Restricted', tone: 'ok' },
  // A user's state (Administration -> Users, ADR-0041).
  user_active: { icon: 'check', text: 'Active', tone: 'ok' },
  user_inactive: { icon: 'blocked', text: 'Inactive', tone: 'idle' },
  user_locked: { icon: 'warning', text: 'Locked', tone: 'warn' },
  door_cloudfox_only: { icon: 'info', text: 'CloudFox only', tone: 'idle' },
}

const look = computed(() => LOOK[props.status] ?? { icon: 'info' as IconName, text: props.status, tone: 'idle' })
</script>

<template>
  <span class="badge" :class="`tone-${look.tone}`">
    <AppIcon :name="look.icon" :size="12" :stroke="2.4" />{{ props.label ?? look.text }}
  </span>
</template>

<style scoped>
/* CatherIs Platform's status pill (design-system.md, Status badge). */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 22px;
  padding: 0 9px;
  border-radius: var(--r-pill);
  font-size: 11px;
  font-weight: 600;
  white-space: nowrap;
}

.tone-ok {
  background: color-mix(in srgb, var(--status-ok) 12%, transparent);
  color: var(--status-ok);
}

.tone-warn {
  background: color-mix(in srgb, var(--status-warn) 12%, transparent);
  color: var(--status-warn);
}

.tone-fail {
  background: color-mix(in srgb, var(--status-fail) 12%, transparent);
  color: var(--status-fail);
}

.tone-live {
  background: color-mix(in srgb, var(--status-run) 12%, transparent);
  color: var(--status-run);
}

.tone-run {
  background: var(--surface-raised);
  color: var(--text-2);
}

.tone-idle {
  background: var(--surface-raised);
  color: var(--status-idle);
}

@media (prefers-reduced-motion: reduce) {
  .tone-live :deep(.spin) {
    animation: none;
  }
}
</style>
