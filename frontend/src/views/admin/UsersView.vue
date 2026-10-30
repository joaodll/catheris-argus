<script setup lang="ts">
/** Administration -> Users (docs/ui/screens.md, E13; ADR-0041): who can sign in, with which
 * role. Admin only (the router and the API both refuse anyone else). */
import { computed, ref } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppPagination from '@/components/AppPagination.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useResource } from '@/composables/useResource'
import { ROLE_LABEL, session } from '@/composables/useSession'
import { toast } from '@/composables/useToasts'
import { relative, utc } from '@/format'
import AddUserModal from './users/AddUserModal.vue'
import EditUserModal from './users/EditUserModal.vue'

const PAGE = 50
const page = ref(1)
const list = useResource(() =>
  unwrap(api.GET('/api/v1/users', { params: { query: { limit: PAGE, offset: (page.value - 1) * PAGE } } })),
)

const adding = ref(false)
const editing = ref<Schemas['UserOut'] | null>(null)

const items = computed(() => list.data.value?.items ?? [])
const activeCount = computed(() => items.value.filter((u) => u.is_active).length)
const activeAdmins = computed(() => items.value.filter((u) => u.is_active && u.role === 'admin').length)

function status(u: Schemas['UserOut']): string {
  if (!u.is_active) return 'user_inactive'
  return u.locked ? 'user_locked' : 'user_active'
}

async function goTo(next: number): Promise<void> {
  page.value = next
  await list.reload()
}

async function onSaved(message: string): Promise<void> {
  adding.value = false
  editing.value = null
  await list.reload()
  toast(message)
}
</script>

<template>
  <PageHeader title="Users">Every change here is recorded in the audit log.</PageHeader>
  <section class="card panel" aria-labelledby="users-h">
    <div class="panel-h">
      <div class="titles">
        <h2 id="users-h" class="h2">Users</h2>
        <span class="cap">
          <template v-if="list.data.value">{{ list.data.value.total }} users · {{ activeCount }} active · </template>roles decide what each can change
        </span>
      </div>
      <button type="button" class="btn btn-primary" @click="adding = true"><AppIcon name="plus" :size="16" :stroke="2.2" />Add user</button>
    </div>

    <div v-if="list.error.value" class="panel-body">
      <AlertBanner kind="fail">
        Users didn't load: {{ list.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="list.reload">Retry</button></template>
      </AlertBanner>
    </div>

    <div v-else-if="!list.data.value" aria-busy="true" class="panel-body loading">
      <div v-for="n in 3" :key="n" class="skeleton sk-48"></div>
    </div>

    <div v-else class="table-wrap table-fit">
      <table class="table stackable stack-narrow dense users-table">
        <thead>
          <tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Last sign-in</th></tr>
        </thead>
        <tbody>
          <tr v-for="u in items" :key="u.id" :class="{ 'is-off': !u.is_active }">
            <td data-label="User" class="name">
              <span class="name-cell">
                <button type="button" class="row-link" @click="editing = u">{{ u.display_name || u.username }}</button>
                <span v-if="u.username === session?.username" class="cap">(you)</span>
              </span>
              <span class="mono sub">{{ u.username }}</span>
            </td>
            <td data-label="Role"><span class="role" :class="{ 'is-admin': u.role === 'admin' }">{{ ROLE_LABEL[u.role] }}</span></td>
            <td data-label="Status" class="status">
              <StatusBadge :status="status(u)" />
              <span v-if="u.must_change_password" class="sub soft">Must change password</span>
            </td>
            <td data-label="Last sign-in">
              <span v-if="u.last_sign_in_at" class="cap" :title="utc(u.last_sign_in_at)">{{ relative(u.last_sign_in_at) }}</span>
              <span v-else class="cap">Never</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <AppPagination v-if="list.data.value" :total="list.data.value.total" :page="page" :limit="PAGE" noun="user" @change="goTo" />
    <p class="panel-foot cap foot">Viewer reads. Operator also runs connections and schedules. Admin also changes Settings and Users.</p>
  </section>

  <AddUserModal v-if="adding" @close="adding = false" @saved="onSaved" />
  <EditUserModal v-if="editing" :user="editing" :active-admins="activeAdmins" @close="editing = null" @saved="onSaved" />
</template>

<style scoped>
.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.name-cell {
  display: inline-flex;
  gap: var(--s-8);
  align-items: center;
  flex-wrap: wrap;
}

.users-table td {
  white-space: nowrap;
}

/* The user column takes what the others leave. */
.users-table td.name {
  width: 100%;
  white-space: normal;
}

.sub {
  display: block;
  margin-top: 3px;
  font-size: 11px;
  color: var(--text-3);
}

.soft {
  font-size: 12px;
  color: var(--text-2);
}

/* A role is an interaction right, not data: the admin's outline is the accent. */
.role {
  display: inline-flex;
  align-items: center;
  height: 22px;
  padding: 0 8px;
  border: 1px solid var(--border-strong);
  border-radius: var(--r-chip);
  font-size: 12px;
  font-weight: 600;
  color: var(--text-2);
}

.role.is-admin {
  border-color: var(--accent);
  color: var(--text);
}

.foot {
  margin: 0;
}
</style>
