<script setup lang="ts">
/**
 * One resource in the Resources page's detail sheet (docs/ui/screens.md, E8). The body is
 * ResourceDetail, which the Resource map's panel shows too. The parent keeps the open id in the
 * URL (?open=).
 */
import { computed, ref } from 'vue'
import type { Schemas } from '@/api/client'
import AppIcon from '@/components/AppIcon.vue'
import SideSheet from '@/components/SideSheet.vue'
import { regionLabel } from './labels'
import ResourceDetail from './ResourceDetail.vue'

// at: a block to bring into view once loaded (#from-internet, from a finding's See the evidence).
const props = defineProps<{ resourceId: number; fallbackTitle: string; connectionName: (id: number) => string; at?: 'from-internet' | null }>()
const emit = defineEmits<{ close: [] }>()

const current = ref<Schemas['ResourceDetail'] | null>(null)
// Until the detail arrives, the header shows the row's name at once.
const title = computed(() => (current.value ? (current.value.name ?? current.value.native_id) : props.fallbackTitle))
const description = computed(() => {
  const r = current.value
  return r ? `${r.type} · ${regionLabel(r.region)} · ${props.connectionName(r.connection_id)}` : ''
})
const resourceLink = (id: number) => ({ name: 'resources', query: { open: String(id) } })
</script>

<template>
  <SideSheet :title="title" :description="description" @close="emit('close')">
    <RouterLink v-if="current" class="btn btn-secondary btn-sm open-map" :to="{ name: 'resource-map', query: { focus: current.resource_uid } }">
      <AppIcon name="graph" :size="16" />Open in map
    </RouterLink>
    <ResourceDetail :resource-id="resourceId" :connection-name="connectionName" :resource-link="resourceLink" :at="at" @loaded="current = $event" />
  </SideSheet>
</template>

<style scoped>
.open-map {
  align-self: flex-start;
}
</style>
