<script setup lang="ts">
/**
 * The Resource map's start (ADR-0051; the spec is in the palace, frontend/c0e9ac9e): with no
 * resource chosen, see what is in the inventory and choose from a type's list, find one by
 * name, or reopen one of the last eight mapped in this tab.
 */
import { ref, watch } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import type { Schemas } from '@/api/client'
import AppIcon from '@/components/AppIcon.vue'
import { clearRecent, forgetRecent, readRecent, type RecentResource } from '@/composables/recentResources'
import { username } from '@/composables/useSession'
import MapStartList from './MapStartList.vue'
import MapStartRow from './MapStartRow.vue'
import MapStartTypes from './MapStartTypes.vue'
import ResourceSearch from './ResourceSearch.vue'
import { typeLabel } from './mapLanes'

const props = defineProps<{
  connections: Schemas['ConnectionOut'][] | null
  connectionsFailed: boolean
  connection: number | null
  connectionName: (id: number) => string
  recentLink: (entry: RecentResource) => RouteLocationRaw
  type: string | null
  page: number
  typeLink: (type: string | null) => RouteLocationRaw
  resourceLink: (row: Schemas['ResourceOut']) => RouteLocationRaw
}>()
const emit = defineEmits<{ choose: [uid: string, connectionId: number]; account: [connectionId: number | null]; page: [page: number] }>()

// Moving between the types and a type's list takes focus to the new heading; arriving does not.
const moved = ref(false)
watch(
  () => props.type,
  () => {
    moved.value = true
  },
)

const recent = ref<RecentResource[]>(readRecent(username.value))
function forget(uid: string): void {
  recent.value = forgetRecent(username.value, uid)
}
function clear(): void {
  clearRecent(username.value)
  recent.value = []
}
const label = (r: RecentResource) => r.name ?? r.uid
// Today's name when the account still exists; the name it had when the resource was opened if not.
const account = (r: RecentResource) =>
  props.connections?.find((c) => c.id === r.connectionId)?.name ?? r.connectionName ?? (r.connectionId != null ? props.connectionName(r.connectionId) : 'Unknown account')
</script>

<template>
  <div class="start">
    <div class="inner">
      <div class="titles">
        <h2 class="h2">Map a resource</h2>
        <p class="cap">Find a resource to see what it connects to: the network it sits in, the roles it runs as, the policies attached and what calls it.</p>
      </div>

      <div class="find-row">
        <div class="field account">
          <label class="lbl" for="map-account">Account</label>
          <select
            id="map-account"
            class="select"
            :value="connection ?? ''"
            :disabled="connections === null && !connectionsFailed"
            @change="emit('account', ($event.target as HTMLSelectElement).value ? Number(($event.target as HTMLSelectElement).value) : null)"
          >
            <option value="">All accounts</option>
            <option v-for="c in connections ?? []" :key="c.id" :value="c.id">{{ c.name }}</option>
          </select>
        </div>
        <ResourceSearch class="search" :connection-name="connectionName" :connection-id="connection" @choose="(uid, cid) => emit('choose', uid, cid)" />
      </div>
      <p v-if="connectionsFailed" class="cap note">Accounts couldn't be loaded; the search covers all of them.</p>

      <section v-if="!type && recent.length" class="recent" aria-labelledby="map-recent-h">
        <div class="recent-head">
          <h3 id="map-recent-h" class="lbl">Recently opened</h3>
          <button type="button" class="btn btn-ghost btn-sm" @click="clear">Clear</button>
        </div>
        <ul class="rows">
          <li v-for="r in recent" :key="r.uid" class="row">
            <MapStartRow
              :to="recentLink(r)"
              :name="label(r)"
              :label="`${label(r)}, ${typeLabel(r.type)}, ${account(r)}`"
              :title="r.uid"
              :type="r.type"
              show-disc
              :meta="`${typeLabel(r.type)} · ${account(r)}`"
            />
            <button type="button" class="forget" :aria-label="`Forget ${label(r)}`" @click="forget(r.uid)">
              <AppIcon name="cross" :size="14" />
            </button>
          </li>
        </ul>
      </section>

      <MapStartList
        v-if="type"
        :key="type"
        :type="type"
        :page="page"
        :connection="connection"
        :connection-name="connectionName"
        :all-types-link="typeLink(null)"
        :resource-link="resourceLink"
        :take-focus="moved"
        @page="(p) => emit('page', p)"
      />
      <MapStartTypes v-else :connection="connection" :type-link="typeLink" :take-focus="moved" />

      <p class="cap hint">Every resource on <RouterLink to="/investigate/resources">Resources</RouterLink> also has Open in Resource Map.</p>
    </div>
  </div>
</template>

<style scoped>
.start {
  display: flex;
  justify-content: center;
  padding: var(--s-32) var(--s-20);
}

.inner {
  display: flex;
  flex-direction: column;
  gap: var(--s-20);
  width: 100%;
  max-width: 720px;
}

.titles {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.titles .h2,
.titles .cap,
.note,
.hint {
  margin: 0;
}

.find-row {
  display: flex;
  align-items: flex-end;
  gap: var(--s-12);
}

.account {
  flex: 0 0 220px;
  min-width: 0;
}

.account .select {
  width: 100%;
}

.search {
  flex: 1 1 auto;
  min-width: 0;
}

.recent {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.recent-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 32px;
}

.recent-head .lbl {
  margin: 0;
}

.rows {
  display: flex;
  flex-direction: column;
  gap: var(--s-2);
  margin: 0;
  padding: 0;
  list-style: none;
}

.row {
  display: flex;
  align-items: center;
  gap: var(--s-4);
  border-radius: var(--r-control);
}

.row:hover,
.row:focus-within {
  background: var(--surface-active);
}

.forget {
  display: inline-flex;
  flex: 0 0 32px;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border: 0;
  border-radius: var(--r-control);
  background: transparent;
  color: var(--text-2);
  cursor: pointer;
}

.forget:hover {
  color: var(--text);
}

.forget:focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
}

@media (max-width: 719px) {
  .start {
    padding: var(--s-20) var(--s-16);
  }

  .find-row {
    flex-direction: column;
    align-items: stretch;
  }

  .account {
    flex-basis: auto;
  }
}
</style>
