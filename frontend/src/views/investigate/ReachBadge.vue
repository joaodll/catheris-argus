<script setup lang="ts">
/**
 * Whether the internet reaches a resource (ADR-0035). On a finding (a CloudFox public endpoint
 * or a Prowler exposure check, sixth amendment): what Argus's internet rules say, labelled with
 * Argus's name and never the other tool's, its reason in words as the tooltip; nothing is shown
 * for a finding without a reach. On a front door (`door`): reachable, unknown (data the verdict
 * needs is missing), restricted, or public to CloudFox alone.
 */
import { computed } from 'vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { reasonWords, type FindingReach } from './reachReason'

type DoorReach = 'open' | 'unknown' | 'restricted' | 'cloudfox_only'

// A finding's reach and reason, or with `door` a front door's reach.
const props = defineProps<{ door?: boolean; reach: FindingReach | DoorReach | null | undefined; reason?: string | null }>()

const DOOR_WHY: Record<DoorReach, string> = {
  open: 'Argus checked its security groups, routing, network ACL, auth and address lists: traffic from the internet can arrive.',
  unknown: 'Public by its settings, but data Argus needs to judge it is missing: it could be reachable.',
  restricted: 'Public by its settings, but security groups, routing, a network ACL, auth or an address list keep the internet out.',
  cloudfox_only: 'Only CloudFox calls it public; no Argus rule confirms it.',
}
const status = computed(() => (props.reach ? `${props.door ? 'door' : 'reach'}_${props.reach}` : null))
const why = computed(() => {
  if (!props.reach) return ''
  if (props.door) return DOOR_WHY[props.reach as DoorReach] ?? ''
  return reasonWords(props.reach as FindingReach, props.reason).text
})
</script>

<template>
  <span v-if="status" class="reach" :title="why">
    <StatusBadge :status="status" />
    <span class="sr-only">{{ why }}</span>
  </span>
</template>

<style scoped>
.reach {
  display: inline-flex;
}
</style>
