<script setup lang="ts">
/** A resource's edges, one row each (docs/ui/screens.md, E8, Connections): direction, type, the
 * resource at the other end, origin. CloudFox's "Attacker view" uses the same rows. */
import type { RouteLocationRaw } from 'vue-router'
import type { Schemas } from '@/api/client'
import { originLabel } from './labels'

type Edge = Schemas['EdgeOut']
const props = defineProps<{ edges: Edge[]; resourceId: number; resourceLink: (id: number) => RouteLocationRaw; newTab?: boolean }>()

function outgoing(e: Edge): boolean {
  return e.source_resource_id === props.resourceId
}
function otherId(e: Edge): number | null {
  return outgoing(e) ? e.target_resource_id : e.source_resource_id
}
function otherName(e: Edge): string | null {
  return outgoing(e) ? e.target_name : e.source_name
}
function otherUid(e: Edge): string {
  return outgoing(e) ? e.target_uid : e.source_uid
}
/** The pseudo-nodes read as words: "Internet", "Admin · 123456789012". */
function pseudo(uid: string): string {
  if (uid === 'internet') return 'Internet'
  if (uid.startsWith('admin:')) return `Admin · ${uid.slice(6)}`
  return uid
}
</script>

<template>
  <ul class="rows">
    <li v-for="e in edges" :key="e.id" class="edge-row">
      <span class="dir" :title="outgoing(e) ? 'Outgoing' : 'Incoming'">
        <span aria-hidden="true">{{ outgoing(e) ? '→' : '←' }}</span><span class="sr-only">{{ outgoing(e) ? 'to' : 'from' }}</span>
      </span>
      <span class="mono type">{{ e.type }}</span>
      <RouterLink
        v-if="otherId(e) != null"
        class="btn btn-ghost btn-sm other"
        :title="otherUid(e)"
        :to="resourceLink(otherId(e)!)"
        :target="newTab ? '_blank' : undefined"
      >
        {{ otherName(e) ?? otherUid(e) }}<span v-if="newTab" class="sr-only"> (opens in a new tab)</span>
      </RouterLink>
      <span v-else class="mono other path">{{ pseudo(otherUid(e)) }}</span>
      <span class="chip" :title="e.origin">{{ originLabel(e.origin) }}</span>
    </li>
  </ul>
</template>

<style scoped>
.rows {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  font-size: 13px;
}

.edge-row {
  display: flex;
  align-items: center;
  gap: var(--s-10);
  min-width: 0;
}

.dir {
  width: 16px;
  color: var(--text-2);
}

.type {
  font-size: 12px;
  color: var(--text-2);
}

.other {
  flex: 1;
  min-width: 0;
  justify-content: flex-start;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.path {
  overflow-wrap: anywhere;
}
</style>
