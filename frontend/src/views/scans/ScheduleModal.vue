<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import CronField from '@/components/CronField.vue'
import AppModal from '@/components/AppModal.vue'
import SwitchToggle from '@/components/SwitchToggle.vue'
import { COLLECTORS, defaultTools, type Collector } from '@/tools'

type Tool = Collector
const props = defineProps<{
  schedule: Schemas['ScheduleOut'] | null
  connections: Schemas['ConnectionOut'][]
  lastRuns: Schemas['LastRun'][] | null
  minInterval: number | null
}>()
const emit = defineEmits<{ close: []; saved: [message: string] }>()

const TOOLS = COLLECTORS.map((c) => ({ id: c.id as Tool, label: c.name }))

const s = props.schedule
const name = ref(s?.name ?? '')
const cron = ref(s?.cron ?? '0 2 * * *')
const allConnections = ref(s ? s.all_connections : true)
const initialChosen = s && !s.all_connections ? [...s.connection_ids].sort((a, b) => a - b) : []
const chosen = ref<number[]>([...initialChosen])
// A new schedule ticks the tools Run now does over its connections (defaultTools: Inspector
// only where it has run), following them until a tick is changed by hand.
const scope = (): number[] => (allConnections.value ? props.connections.filter((c) => c.enabled).map((c) => c.id) : chosen.value)
const initialTools = (s?.tools as Tool[] | undefined) ?? defaultTools(props.lastRuns ?? [], scope())
const tools = ref<Tool[]>([...initialTools])
const toolsTouched = ref(false)
if (!s) {
  watch(
    [allConnections, chosen, () => props.lastRuns, () => props.connections],
    () => {
      if (!toolsTouched.value) tools.value = defaultTools(props.lastRuns ?? [], scope())
    },
    { deep: true },
  )
}
const enabled = ref(s?.enabled ?? true)
const cronValid = ref(true)
const saving = ref(false)
const error = ref<string | null>(null)

const dirty = computed(
  () =>
    name.value !== (s?.name ?? '') ||
    (s ? orderedTools().join() !== initialTools.join() : toolsTouched.value) ||
    cron.value !== (s?.cron ?? '0 2 * * *') ||
    enabled.value !== (s?.enabled ?? true) ||
    allConnections.value !== (s ? s.all_connections : true) ||
    (!allConnections.value && [...chosen.value].sort((a, b) => a - b).join() !== initialChosen.join()),
)
const canSave = computed(
  () => !saving.value && cronValid.value && name.value.trim() !== '' && tools.value.length > 0 && (allConnections.value || chosen.value.length > 0),
)

function orderedTools(): Tool[] {
  return TOOLS.map((t) => t.id).filter((id) => tools.value.includes(id))
}

async function save(): Promise<void> {
  saving.value = true
  error.value = null
  const body = {
    name: name.value.trim(),
    tools: orderedTools(),
    cron: cron.value.trim(),
    connection_ids: allConnections.value ? null : chosen.value,
    enabled: enabled.value,
  }
  try {
    if (s) {
      await unwrap(api.PUT('/api/v1/schedules/{schedule_id}', { params: { path: { schedule_id: s.id } }, body }))
      emit('saved', `${body.name} saved. The worker uses it from its next minute.`)
    } else {
      await unwrap(api.POST('/api/v1/schedules', { body }))
      emit('saved', `${body.name} created. The worker picks it up within a minute.`)
    }
  } catch (err) {
    error.value = err instanceof ApiError && err.status === 409 ? 'A schedule with this name already exists.' : err instanceof ApiError ? err.message : 'The schedule was not saved.'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <AppModal :title="s ? s.name : 'New schedule'" description="The worker picks changes up within a minute. No restart." :dirty="dirty" @close="emit('close')">
    <form id="schedule-form" class="form" @submit.prevent="save">
      <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
      <div class="field">
        <label class="lbl" for="s-name">Name</label>
        <input id="s-name" v-model="name" class="input" required maxlength="100">
      </div>
      <div class="field">
        <fieldset class="tools" aria-describedby="s-tools-help">
          <legend class="lbl">Tools</legend>
          <label v-for="t in TOOLS" :key="t.id" class="check">
            <input v-model="tools" type="checkbox" :value="t.id" @change="toolsTouched = true">
            {{ t.label }}
          </label>
        </fieldset>
        <span v-if="tools.length === 0" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />Choose at least one tool.</span>
        <span id="s-tools-help" class="cap">Each tool is its own run. On the same account they run one at a time, in this order.<template v-if="!s"> Inspector starts ticked only where it has already run.</template></span>
      </div>
      <CronField v-model="cron" :min-interval="props.minInterval" @valid="(ok) => (cronValid = ok)" />
      <fieldset class="scope">
        <legend class="lbl">Scope</legend>
        <label class="check"><input v-model="allConnections" type="radio" name="scope" :value="true">All connections, including ones added later</label>
        <label class="check"><input v-model="allConnections" type="radio" name="scope" :value="false">Only these connections</label>
        <div v-if="!allConnections" class="choices">
          <label v-for="c in props.connections" :key="c.id" class="check"><input v-model="chosen" type="checkbox" :value="c.id">{{ c.name }}</label>
          <span v-if="chosen.length === 0" class="cap">Choose at least one connection.</span>
        </div>
      </fieldset>
      <div class="field">
        <span class="lbl">State</span>
        <SwitchToggle v-model="enabled" label="Schedule state" />
      </div>
    </form>
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">Cancel</button>
      <button type="submit" form="schedule-form" class="btn btn-primary" :disabled="!canSave">
        <AppIcon v-if="saving" name="spinner" :size="16" :stroke="2.4" />{{ saving ? 'Saving…' : s ? 'Save schedule' : 'Create schedule' }}
      </button>
    </template>
  </AppModal>
</template>

<style scoped>
.tools {
  display: flex;
  gap: var(--s-20);
  flex-wrap: wrap;
}

.form {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.scope {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.choices {
  display: flex;
  flex-direction: column;
  padding-left: 28px;
}
</style>
