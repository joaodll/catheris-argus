<script setup lang="ts">
import { computed, ref } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import EmptyState from '@/components/EmptyState.vue'
import MaskedValue from '@/components/MaskedValue.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import SwitchToggle from '@/components/SwitchToggle.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import { can } from '@/composables/useSession'
import { toast } from '@/composables/useToasts'
import { relative, utc } from '@/format'
import AddConnectionModal from './AddConnectionModal.vue'
import EditConnectionModal from './EditConnectionModal.vue'

const TOOLS = ['steampipe', 'prowler', 'cloudfox']

const list = useResource(() => unwrap(api.GET('/api/v1/connections')))
const context = useResource(() => unwrap(api.GET('/api/v1/context', { params: { query: { connection_id: 0 } } })))
// Demo connections are offered on Docker Compose only; on Kubernetes the API offers AWS alone.
const kinds = useResource(() => unwrap(api.GET('/api/v1/connections/kinds')))
const demoOffered = computed(() => (kinds.data.value ?? []).includes('demo'))

const adding = ref(false)
// A Viewer reads connections; an Operator or Admin changes them (ADR-0041).
const operator = computed(() => can('operator'))
const editing = ref<Schemas['ConnectionOut'] | null>(null)
const busy = ref<Set<number>>(new Set())

const enabledCount = computed(() => (list.data.value ?? []).filter((c) => c.enabled).length)

function runsOf(id: number): { tool: string; run: Schemas['LastRun'] | undefined }[] {
  const runs = context.data.value?.last_runs ?? []
  return TOOLS.map((tool) => ({ tool, run: runs.find((r) => r.connection_id === id && r.tool === tool) }))
}

function roleName(arn: string | null): string {
  return arn ? (arn.split(':role/')[1] ?? arn) : ''
}

async function setEnabled(c: Schemas['ConnectionOut'], enabled: boolean): Promise<void> {
  busy.value = new Set(busy.value).add(c.id)
  try {
    await unwrap(api.PATCH('/api/v1/connections/{connection_id}', { params: { path: { connection_id: c.id } }, body: { enabled } }))
    await list.reload()
    toast(`${c.name} ${enabled ? 'enabled' : 'disabled'}.`)
  } catch (err) {
    toast(err instanceof ApiError ? err.message : 'The change was not saved.', 'error')
  } finally {
    const next = new Set(busy.value)
    next.delete(c.id)
    busy.value = next
  }
}

async function onSaved(message: string): Promise<void> {
  adding.value = false
  editing.value = null
  await Promise.all([list.reload(), context.reload()])
  toast(message)
}
</script>

<template>
  <PageHeader title="Connections">Every change here is recorded in the audit log.</PageHeader>
  <!-- The Platform's list panel: a header bar, the table edge to edge, a footer bar. -->
  <section class="card panel" aria-labelledby="conn-h">
    <div class="panel-h">
      <div class="titles">
        <h2 id="conn-h" class="h2">Connections</h2>
        <span class="cap">
          <template v-if="list.data.value">{{ list.data.value.length }} connections · {{ enabledCount }} enabled · </template>the accounts Argus collects from
        </span>
      </div>
      <button v-if="operator" type="button" class="btn btn-primary" @click="adding = true"><AppIcon name="plus" :size="16" :stroke="2.2" />Add connection</button>
    </div>

    <div v-if="list.error.value" class="panel-body">
      <AlertBanner kind="fail">
        Connections didn't load: {{ list.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="list.reload">Retry</button></template>
      </AlertBanner>
    </div>

    <div v-else-if="!list.data.value" aria-busy="true" class="panel-body loading">
      <div v-for="n in 3" :key="n" class="skeleton sk-48"></div>
    </div>

    <div v-else-if="list.data.value.length === 0" class="panel-body">
      <EmptyState
        title="No connections yet."
        :text="demoOffered ? 'Add a Demo connection to explore Argus with synthetic data, or connect an AWS account.' : 'Connect an AWS account.'"
      >
        <button v-if="operator" type="button" class="btn btn-secondary" @click="adding = true">Add connection</button>
      </EmptyState>
    </div>

    <div v-else class="table-wrap table-fit">
      <table class="table stackable stack-narrow dense connections-table">
        <thead>
          <tr><th scope="col">Name</th><th scope="col">Sign-in</th><th scope="col">Last runs</th><th scope="col">Enabled</th></tr>
        </thead>
        <tbody>
          <tr v-for="c in list.data.value" :key="c.id" :class="{ 'is-off': !c.enabled }">
            <td data-label="Name" class="name">
              <span class="name-cell">
                <button type="button" class="row-link" @click="editing = c">{{ c.name }}</button>
                <span class="chip">{{ c.kind === 'demo' ? 'Demo' : 'AWS' }}</span>
              </span>
              <span class="mono sub">{{ c.account_id }}</span>
            </td>
            <td data-label="Sign-in">
              <span v-if="c.kind === 'demo'">Synthetic</span>
              <span v-else-if="c.auth_method === 'assume_role'">Assume role <span class="mono soft">{{ roleName(c.role_arn) }}</span></span>
              <span v-else>Access key <span class="mono">{{ c.access_key_id_hint }}</span></span>
              <span v-if="c.kind !== 'demo' && c.auth_method === 'assume_role'" class="cred">
                <template v-if="c.external_id_set">External ID <MaskedValue /></template>
                <template v-else>No external ID</template>
              </span>
              <span v-else-if="c.kind !== 'demo'" class="cred">Secret <MaskedValue /> · set on <span class="mono">{{ c.secret_set_at?.slice(0, 10) ?? '—' }}</span></span>
            </td>
            <td data-label="Last runs">
              <div class="runs">
                <template v-for="r in runsOf(c.id)" :key="r.tool">
                  <template v-if="r.run">
                    <ToolChip :tool="r.tool" />
                    <StatusBadge :status="r.run.status" />
                    <span class="cap" :title="utc(r.run.finished_at)">{{ relative(r.run.finished_at) }}</span>
                  </template>
                </template>
                <span v-if="runsOf(c.id).every((r) => !r.run)" class="cap">Not run yet</span>
              </div>
            </td>
            <td data-label="Enabled">
              <span v-if="!operator">{{ c.enabled ? 'Enabled' : 'Disabled' }}</span>
              <SwitchToggle
                v-else
                :model-value="c.enabled"
                :busy="busy.has(c.id)"
                :label="`Collection for ${c.name}`"
                @update:model-value="(v) => setEnabled(c, v)"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="panel-foot cap foot">Connections are disabled, never deleted: their history stays. Last runs show the latest of each tool.</p>
  </section>

  <AddConnectionModal
    v-if="adding"
    :demo="demoOffered"
    @close="adding = false"
    @saved="onSaved"
  />
  <EditConnectionModal v-if="editing" :connection="editing" :readonly="!operator" @close="editing = null" @saved="onSaved" />
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

.soft {
  color: var(--text-2);
}

.runs {
  display: grid;
  grid-template-columns: auto auto auto;
  gap: var(--s-4) var(--s-8);
  align-items: center;
  justify-content: start;
}

.runs .cap {
  white-space: nowrap;
}

.foot {
  margin: 0;
}

.connections-table td {
  white-space: nowrap;
}

/* The name column takes what the others leave. */
.connections-table td.name {
  width: 100%;
  white-space: normal;
}

.sub {
  display: block;
  margin-top: 3px;
  font-size: 11px;
  color: var(--text-3);
}

.cred {
  display: block;
  margin-top: 3px;
  font-size: 12px;
  color: var(--text-2);
}
</style>
