<script setup lang="ts">
/**
 * One type's resources on the Resource map's start, a page at a time. Choosing a row maps it. The
 * heading counts this list, so a page never contradicts itself.
 */
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import EmptyState from '@/components/EmptyState.vue'
import { useResource } from '@/composables/useResource'
import { regionLabel } from '../labels'
import MapStartRow from './MapStartRow.vue'
import { typeDisc, typeLabel } from './mapLanes'

const props = defineProps<{
  type: string
  page: number
  connection: number | null
  connectionName: (id: number) => string
  allTypesLink: RouteLocationRaw
  resourceLink: (row: Schemas['ResourceRow']) => RouteLocationRaw
  takeFocus: boolean
}>()
const emit = defineEmits<{ page: [page: number] }>()

const PAGE = 20
const list = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/resources', {
        params: { query: { type: props.type, connection_id: props.connection ?? undefined, limit: PAGE, offset: (props.page - 1) * PAGE } },
      }),
    ),
  { watch: [() => props.type, () => props.page, () => props.connection] },
)
const total = computed(() => list.data.value?.total ?? 0)
const lastPage = computed(() => Math.max(1, Math.ceil(total.value / PAGE)))
// The list can shrink under a kept page: another account, or a newer scan. Show the last page.
watch(
  () => list.data.value,
  (data) => {
    if (data && props.page > lastPage.value) emit('page', lastPage.value)
  },
)
const label = computed(() => typeLabel(props.type))
const showsRaw = computed(() => label.value !== props.type)
const counted = computed(() => `${total.value.toLocaleString('en-US')} ${total.value === 1 ? 'resource' : 'resources'}`)
const name = (r: Schemas['ResourceRow']) => r.name ?? r.native_id
const where = (r: Schemas['ResourceRow']) =>
  props.connection == null ? `${props.connectionName(r.connection_id)} · ${regionLabel(r.region)}` : regionLabel(r.region)

const heading = ref<HTMLElement | null>(null)
onMounted(() => {
  if (props.takeFocus) heading.value?.focus()
})
function goTo(page: number): void {
  emit('page', page)
  void nextTick(() => heading.value?.focus()) // the new rows are announced
}
</script>

<template>
  <section class="list" aria-labelledby="map-type-h" :aria-busy="list.loading.value">
    <RouterLink class="btn btn-ghost btn-sm back" :to="allTypesLink">
      <AppIcon name="chevron" :size="14" :stroke="2.2" class="prev" />All types
    </RouterLink>
    <div class="head">
      <span class="disc" :style="{ '--type': typeDisc('resource', type).color }" aria-hidden="true">
        <AppIcon :name="typeDisc('resource', type).icon" :size="15" />
      </span>
      <div class="titles">
        <h3 id="map-type-h" ref="heading" class="h3-type" tabindex="-1">{{ label }}</h3>
        <span class="cap">
          <span v-if="showsRaw" class="mono">{{ type }}</span>
          <template v-if="list.data.value && total > 0"><template v-if="showsRaw"> · </template>{{ counted }}</template>
        </span>
      </div>
    </div>

    <AlertBanner v-if="list.error.value" kind="fail">
      These resources didn't load: {{ list.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="list.reload">Retry</button></template>
    </AlertBanner>
    <div v-else-if="list.data.value === null" class="loading">
      <div v-for="n in 5" :key="n" class="skeleton sk-48"></div>
    </div>
    <EmptyState v-else-if="total === 0" icon="info" title="No resources of this type in this account.">
      <RouterLink class="btn btn-secondary" :to="allTypesLink">All types</RouterLink>
    </EmptyState>
    <template v-else>
      <ul class="rows">
        <li v-for="r in list.data.value.items" :key="r.id">
          <MapStartRow
            :to="resourceLink(r)"
            :name="name(r)"
            :label="`${name(r)}, ${where(r)}`"
            :title="r.resource_uid"
            :mono="r.name == null"
            :meta="where(r)"
          />
        </li>
      </ul>
      <AppPagination :total="total" :page="page" :limit="PAGE" noun="resource" @change="goTo" />
    </template>
  </section>
</template>

<style scoped>
.list,
.rows,
.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.list {
  gap: var(--s-12);
}

.back {
  align-self: flex-start;
}

.prev {
  transform: rotate(180deg);
}

.head {
  display: flex;
  align-items: center;
  gap: var(--s-12);
}

.disc {
  display: inline-flex;
  flex: 0 0 28px;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: color-mix(in srgb, var(--type) 16%, transparent);
  color: var(--type);
}

.titles {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.h3-type {
  margin: 0;
  color: var(--text);
  font-size: 14px;
  font-weight: 600;
}

.h3-type:focus {
  outline: none;
}

.cap {
  overflow-wrap: anywhere;
}

.rows {
  gap: var(--s-2);
  margin: 0;
  padding: 0;
  list-style: none;
}

.rows li {
  display: flex;
  min-width: 0;
}
</style>
