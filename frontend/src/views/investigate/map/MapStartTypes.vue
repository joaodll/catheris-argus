<script setup lang="ts">
/**
 * "What's here": the Resource map's start without a name to search for. The inventory's types with
 * their counts, the Overview's numbers and groups, largest first in a group. Choosing a type lists
 * its resources (MapStartList).
 */
import { computed, onMounted, ref } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import EmptyState from '@/components/EmptyState.vue'
import { useResource } from '@/composables/useResource'
import { groupTypes } from '@/views/overview/assetTypes'
import MapStartRow from './MapStartRow.vue'
import { typeLabel } from './mapLanes'

const props = defineProps<{
  connection: number | null
  typeLink: (type: string) => RouteLocationRaw
  takeFocus: boolean
}>()

// The Resources Summary's stored counts, read through the map's own plain route (no risk count
// reaches the Resource Map): every asset type of one account or of all, so the screens agree.
const types = useResource(
  () => unwrap(api.GET('/api/v1/map/types', { params: { query: { connection_id: props.connection ?? 0 } } })),
  { watch: [() => props.connection] },
)
const rows = computed(() => types.data.value?.by_type ?? [])
const groups = computed(() => groupTypes(rows.value))
const countOf = computed(() => new Map(rows.value.map((t) => [t.type, t.count])))
// A label several types share (API Gateway): their raw types tell them apart.
const shared = computed(() => {
  const seen = new Map<string, number>()
  for (const { type } of rows.value) seen.set(typeLabel(type), (seen.get(typeLabel(type)) ?? 0) + 1)
  return seen
})
const resources = (n: number) => `${n.toLocaleString('en-US')} ${n === 1 ? 'resource' : 'resources'}`

const heading = ref<HTMLElement | null>(null)
onMounted(() => {
  if (props.takeFocus) heading.value?.focus()
})
</script>

<template>
  <section class="types" aria-labelledby="map-types-h" :aria-busy="types.loading.value">
    <div class="head">
      <h3 id="map-types-h" ref="heading" class="lbl" tabindex="-1">What's here</h3>
      <span v-if="types.data.value?.data_through" class="cap">Data through <span class="mono strong">{{ types.data.value.data_through }}</span></span>
    </div>

    <AlertBanner v-if="types.error.value" kind="fail">
      Resource types didn't load: {{ types.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="types.reload">Retry</button></template>
    </AlertBanner>
    <div v-else-if="types.data.value === null" class="loading">
      <div v-for="n in 5" :key="n" class="skeleton sk-48"></div>
    </div>
    <EmptyState v-else-if="rows.length === 0 && !types.data.value.data_through" icon="stack" title="No resources yet." text="The inventory appears after a Steampipe scan is ingested.">
      <RouterLink class="btn btn-ghost" :to="{ name: 'schedules' }">Go to Schedules</RouterLink>
    </EmptyState>
    <!-- Scanned, but nothing to count: only parts and settings, or a scan older than the counts keep. -->
    <EmptyState v-else-if="rows.length === 0" icon="info" title="No resource types to show." text="Search by name, id or ARN still covers the whole inventory." />
    <template v-else>
      <div v-for="group in groups" :key="group.name" class="group">
        <h4 class="lbl group-name">{{ group.name }}</h4>
        <ul class="grid">
          <li v-for="type in group.types" :key="type">
            <MapStartRow
              :to="typeLink(type)"
              :name="typeLabel(type)"
              :label="`${typeLabel(type)}, ${resources(countOf.get(type) ?? 0)}`"
              :title="type"
              :type="type"
              show-disc
              :meta="(shared.get(typeLabel(type)) ?? 0) > 1 ? type : undefined"
              mono-meta
              :count="countOf.get(type)"
            />
          </li>
        </ul>
      </div>
    </template>
  </section>
</template>

<style scoped>
.types,
.group,
.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.types {
  gap: var(--s-16);
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-12);
  min-height: 32px;
}

.head .lbl,
.group-name {
  margin: 0;
}

.head .lbl:focus {
  outline: none;
}

.group-name {
  color: var(--text-2);
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(280px, 100%), 1fr));
  gap: var(--s-2) var(--s-12);
  margin: 0;
  padding: 0;
  list-style: none;
}

.grid li {
  display: flex;
  min-width: 0;
}
</style>
