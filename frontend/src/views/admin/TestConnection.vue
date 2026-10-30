<script setup lang="ts">
/**
 * Test connection (ADR-0024, amended 2026-10-07): the worker signs in as the saved connection
 * or platform identity and says what happened. The API only queues the test (it has no route
 * out), so the result is polled until the worker answers, usually within seconds.
 */
import { onBeforeUnmount, ref } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'

const props = defineProps<{
  target: 'connection' | 'identity'
  connectionId?: number
  // Unsaved changes: the test would use what is saved, so it waits for a save.
  dirty?: boolean
}>()

const POLL_MS = 1500
const busy = ref(false)
const result = ref<Schemas['TestOut'] | null>(null)
const error = ref<string | null>(null)
let timer: number | undefined
let stopped = false

async function poll(id: number): Promise<void> {
  try {
    const answer = await unwrap(api.GET('/api/v1/connection-tests/{test_id}', { params: { path: { test_id: id } } }))
    if (stopped) return
    if (answer.status === 'queued' || answer.status === 'running') {
      timer = window.setTimeout(() => void poll(id), POLL_MS)
      return
    }
    result.value = answer
    busy.value = false
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The result did not load.'
    busy.value = false
  }
}

async function run(): Promise<void> {
  busy.value = true
  result.value = null
  error.value = null
  try {
    const queued =
      props.target === 'connection' && props.connectionId != null
        ? await unwrap(api.POST('/api/v1/connections/{connection_id}/test', { params: { path: { connection_id: props.connectionId } } }))
        : await unwrap(api.POST('/api/v1/settings/identity/test'))
    await poll(queued.id)
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The test did not start.'
    busy.value = false
  }
}

onBeforeUnmount(() => {
  stopped = true
  window.clearTimeout(timer)
})
</script>

<template>
  <div class="test" aria-live="polite">
    <div class="row">
      <button type="button" class="btn btn-secondary btn-sm" :disabled="busy || props.dirty" @click="run">
        <AppIcon v-if="busy" name="spinner" :size="16" :stroke="2.4" />{{ busy ? 'Testing…' : 'Test connection' }}
      </button>
      <span v-if="props.dirty" class="cap">Save first: the test signs in with what is saved.</span>
      <span v-else-if="busy" class="cap">The worker is signing in. This takes a few seconds.</span>
      <span v-else-if="!result && !error" class="cap">
        {{ props.target === 'identity' ? 'Signs in, then writes a small test object to each tool folder of the raw output bucket.' : 'Signs in as a scan would and checks the account. Reads and changes nothing in it.' }}
      </span>
    </div>
    <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
    <AlertBanner v-else-if="result" :kind="result.status === 'passed' ? 'ok' : 'fail'">
      <b>{{ result.status === 'passed' ? 'Passed.' : 'Failed.' }}</b> {{ result.message }}
      <span v-if="result.caller_arn" class="mono arn">{{ result.caller_arn }}</span>
    </AlertBanner>
  </div>
</template>

<style scoped>
.test {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-10);
}

.row .cap {
  margin: 0;
}

.arn {
  display: block;
  margin-top: var(--s-4);
  font-size: 12px;
  overflow-wrap: anywhere;
}
</style>
