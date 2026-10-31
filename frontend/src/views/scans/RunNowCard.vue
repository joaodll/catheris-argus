<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import { COLLECTOR_IDS, COLLECTORS, collectorName, defaultTools, type Collector } from '@/tools'
import { cooldownNote, refusedBecause } from './runNotes'

type Tool = Collector
const props = defineProps<{
  connections: Schemas['ConnectionOut'][] | null
  lastRuns: Schemas['LastRun'][] | null
  cooldown: number | null
}>()
const emit = defineEmits<{ queued: [] }>()

// Until settings load, the default cooldown (settings/topics.py).
const cooldown = computed(() => props.cooldown ?? 60)
const enabledConnections = computed(() => (props.connections ?? []).filter((c) => c.enabled))
const chosen = ref<number[]>([])
const tools = ref<Tool[]>(defaultTools([], []))
// The ticks follow the chosen connections (defaultTools) until a tick is changed by hand.
const toolsTouched = ref(false)
const busy = ref(false)
const queued = ref<string | null>(null)
const refused = ref<string | null>(null)
const error = ref<string | null>(null)

watch(enabledConnections, (list) => {
  if (chosen.value.length === 0 && list.length === 1 && list[0]) chosen.value = [list[0].id]
})
watch(
  [chosen, () => props.lastRuns],
  () => {
    if (!toolsTouched.value) tools.value = defaultTools(props.lastRuns ?? [], chosen.value)
  },
  { deep: true },
)

function describe(items: { connection_id: number; tool: string }[]): string {
  return items
    .map((i) => `${collectorName(i.tool)} on ${props.connections?.find((c) => c.id === i.connection_id)?.name ?? `#${i.connection_id}`}`)
    .join(', ')
}

async function run(): Promise<void> {
  busy.value = true
  queued.value = refused.value = error.value = null
  try {
    const order = COLLECTOR_IDS
    const result = await unwrap(
      api.POST('/api/v1/run-requests', { body: { connection_ids: chosen.value, tools: order.filter((t) => tools.value.includes(t)) } }),
    )
    queued.value = `Queued ${result.queued.length} run${result.queued.length === 1 ? '' : 's'}: ${describe(result.queued)}.`
    if (result.refused.length) refused.value = `Skipped, ${refusedBecause(cooldown.value)}: ${describe(result.refused)}.`
    emit('queued')
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      const list = (err.detail as { refused?: { connection_id: number; tool: string }[] } | null)?.refused ?? []
      error.value = `Nothing queued: every tool you chose is ${refusedBecause(cooldown.value)}${list.length ? ` (${describe(list)})` : ''}. A run still waiting, such as a retry, can be cancelled in the Queue.`
    } else {
      error.value = err instanceof ApiError ? err.message : 'Nothing was queued.'
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card stack" aria-labelledby="rn-h">
    <div class="titles">
      <h2 id="rn-h" class="h2">Run now</h2>
      <span class="cap">Starts tools outside their schedule. They queue behind runs already waiting.</span>
    </div>
    <fieldset>
      <legend class="lbl">Connections</legend>
      <label v-for="c in enabledConnections" :key="c.id" class="check"><input v-model="chosen" type="checkbox" :value="c.id">{{ c.name }}</label>
      <span v-if="props.connections && enabledConnections.length === 0" class="cap">No enabled connections.</span>
      <button v-if="enabledConnections.length > 1" type="button" class="btn btn-ghost btn-sm select-all" @click="chosen = enabledConnections.map((c) => c.id)">Select all</button>
    </fieldset>
    <fieldset aria-describedby="rn-tools-help">
      <legend class="lbl">Tools, in run order</legend>
      <span id="rn-tools-help" class="cap">Vulnerabilities starts ticked only where it has already run.</span>
      <div class="tools">
        <label v-for="c in COLLECTORS" :key="c.id" class="check"><input v-model="tools" type="checkbox" :value="c.id" @change="toolsTouched = true">{{ c.name }}</label>
      </div>
    </fieldset>
    <div class="go">
      <button type="button" class="btn btn-primary" :disabled="busy || chosen.length === 0 || tools.length === 0" @click="run">
        <AppIcon v-if="busy" name="spinner" :size="16" :stroke="2.4" />{{ busy ? 'Queueing…' : 'Run now' }}
      </button>
      <span class="cap">{{ cooldownNote(cooldown) }}</span>
    </div>
    <AlertBanner v-if="queued" kind="ok">{{ queued }}</AlertBanner>
    <AlertBanner v-if="refused" kind="warn">{{ refused }}</AlertBanner>
    <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
  </section>
</template>

<style scoped>
.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.select-all {
  padding: 0;
}

.tools {
  display: flex;
  gap: var(--s-16);
  flex-wrap: wrap;
}

.go {
  display: flex;
  gap: var(--s-12);
  align-items: center;
  flex-wrap: wrap;
}

.go .cap {
  flex: 1;
  min-width: 220px;
}
</style>
