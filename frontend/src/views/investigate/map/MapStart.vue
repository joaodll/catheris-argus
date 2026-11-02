<script setup lang="ts">
/**
 * The Resource map's start (round M3a; the spec is in the palace, frontend): with no resource
 * chosen, find one (in one account, or in all) or reopen one of the last eight mapped in this
 * tab. The map shows dependencies and connections; what the internet reaches is explained on
 * Attack paths and Findings, so nothing here judges reach.
 */
import { ref } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import type { Schemas } from '@/api/client'
import AppIcon from '@/components/AppIcon.vue'
import { clearRecent, forgetRecent, readRecent, type RecentResource } from '@/composables/recentResources'
import { username } from '@/composables/useSession'
import ResourceSearch from './ResourceSearch.vue'
import { typeDisc, typeLabel } from './mapLanes'

const props = defineProps<{
  connections: Schemas['ConnectionOut'][] | null
  connectionsFailed: boolean
  connection: number | null
  connectionName: (id: number) => string
  recentLink: (entry: RecentResource) => RouteLocationRaw
}>()
const emit = defineEmits<{ choose: [uid: string, connectionId: number]; account: [connectionId: number | null] }>()

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

      <section class="recent" aria-labelledby="map-recent-h">
        <div class="recent-head">
          <h3 id="map-recent-h" class="lbl">Recently opened</h3>
          <button v-if="recent.length" type="button" class="btn btn-ghost btn-sm" @click="clear">Clear</button>
        </div>
        <ul v-if="recent.length" class="rows">
          <li v-for="r in recent" :key="r.uid" class="row">
            <RouterLink class="open" :to="recentLink(r)" :title="r.uid" :aria-label="`${label(r)}, ${typeLabel(r.type)}, ${account(r)}`">
              <span class="disc" :style="{ '--type': typeDisc('resource', r.type).color }" aria-hidden="true">
                <AppIcon :name="typeDisc('resource', r.type).icon" :size="15" />
              </span>
              <span class="text">
                <span class="name">{{ label(r) }}</span>
                <span class="meta">{{ typeLabel(r.type) }} · {{ account(r) }}</span>
              </span>
            </RouterLink>
            <button type="button" class="forget" :aria-label="`Forget ${label(r)}`" @click="forget(r.uid)">
              <AppIcon name="cross" :size="14" />
            </button>
          </li>
        </ul>
        <p v-else class="empty">Resources you open on the map appear here.</p>
      </section>

      <p class="cap hint">
        Every resource on <RouterLink to="/investigate/resources">Resources</RouterLink> and every step on
        <RouterLink to="/investigate/attack-paths">Attack paths</RouterLink> also has Open in map.
      </p>
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

.open {
  display: flex;
  flex: 1 1 auto;
  align-items: center;
  gap: var(--s-12);
  min-width: 0;
  min-height: 44px;
  padding: var(--s-6) var(--s-8);
  border-radius: var(--r-control);
  color: inherit;
  text-decoration: none;
}

.open:focus-visible,
.forget:focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
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

.text {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.name {
  overflow: hidden;
  color: var(--text);
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.meta {
  overflow: hidden;
  color: var(--text-2);
  font-size: 12.5px;
  text-overflow: ellipsis;
  white-space: nowrap;
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

.empty {
  margin: 0;
  color: var(--text-3);
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
