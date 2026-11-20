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
import { can } from '@/composables/useSession'
import { toast } from '@/composables/useToasts'
import ReportModal from '@/views/scans/ReportModal.vue'
import { regionLabel } from './labels'
import ResourceDetail from './ResourceDetail.vue'

// at: a block to bring into view once loaded (#from-internet, from a finding's See the evidence).
const props = defineProps<{ resourceId: number; fallbackTitle: string; connectionName: (id: number) => string; at?: 'from-internet' | null }>()
const emit = defineEmits<{ close: [] }>()

// Only name, type, region and uid are read here, which both reads carry.
const current = ref<Schemas['ResourceOut'] | null>(null)
// Until the detail arrives, the header shows the row's name at once.
const title = computed(() => (current.value ? (current.value.name ?? current.value.native_id) : props.fallbackTitle))
const description = computed(() => {
  const r = current.value
  return r ? `${r.type} · ${regionLabel(r.region)} · ${props.connectionName(r.connection_id)}` : ''
})
const resourceLink = (id: number) => ({ name: 'resources', query: { open: String(id) } })
// This resource's open misconfigurations and CVEs as a report (ADR-0047 3d): Operator and Admin.
const operator = computed(() => can('operator'))
const exporting = ref(false)
function onExported(id: number): void {
  exporting.value = false
  toast(`Report #${id} requested. Operate → Reports has it when it is ready.`)
}
</script>

<template>
  <SideSheet :title="title" :description="description" @close="emit('close')">
    <div v-if="current" class="open-maps">
      <RouterLink class="btn btn-secondary btn-sm" :to="{ name: 'map', query: { focus: current.resource_uid } }">
        <AppIcon name="graph" :size="16" />Open on Map
      </RouterLink>
      <RouterLink class="btn btn-secondary btn-sm" :to="{ name: 'map', query: { focus: current.resource_uid, mode: 'security' } }">
        <AppIcon name="shield" :size="16" />Open on Map, Security view
      </RouterLink>
      <button v-if="operator" type="button" class="btn btn-secondary btn-sm" @click="exporting = true">
        <AppIcon name="download" :size="16" />Export its problems
      </button>
    </div>
    <ReportModal
      v-if="exporting && current"
      kind="resource-problems"
      :filters="{ resource_id: current.id, connection_id: [current.connection_id] }"
      :connections="[]"
      :account-name="connectionName"
      @close="exporting = false"
      @requested="onExported"
    />
    <ResourceDetail :resource-id="resourceId" :connection-name="connectionName" :resource-link="resourceLink" :at="at" @loaded="current = $event" />
  </SideSheet>
</template>

<style scoped>
.open-maps {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-8);
}
</style>
