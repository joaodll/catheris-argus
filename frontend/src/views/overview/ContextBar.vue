<script setup lang="ts">
import { COLLECTOR_IDS } from '@/tools'
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import StatusBadge from '@/components/StatusBadge.vue'
import ToolChip from '@/components/ToolChip.vue'
import { longDate, relative, utc } from '@/format'

const props = defineProps<{
  context: Schemas['Context'] | null
  overview: Schemas['Overview'] | null
  connectionId: number
}>()
const emit = defineEmits<{ selectConnection: [id: number] }>()

const TOOLS = COLLECTOR_IDS

/** The latest run of each tool for the selection (across connections when "all"). */
const lastRuns = computed(() =>
  TOOLS.map((tool) => {
    const runs = (props.context?.last_runs ?? []).filter((r) => r.tool === tool)
    const latest = runs.sort((a, b) => (b.finished_at ?? '').localeCompare(a.finished_at ?? ''))[0]
    const troubled = runs.filter((r) => r.status !== 'complete')
    return { tool, latest, troubled }
  }),
)
const dataThrough = computed(() => props.overview?.data_through ?? null)
</script>

<template>
  <section class="card bar" aria-label="Context">
    <div class="field">
      <label class="lbl" for="ctx-provider">Provider</label>
      <div class="provider">
        <select id="ctx-provider" class="select" disabled>
          <option>AWS</option>
        </select>
        <span class="cap">GCP and OCI: not covered</span>
      </div>
    </div>
    <div class="field">
      <label class="lbl" for="ctx-account">Accounts</label>
      <select
        id="ctx-account"
        class="select"
        :value="props.connectionId"
        @change="emit('selectConnection', Number(($event.target as HTMLSelectElement).value))"
      >
        <option :value="0">All connections ({{ props.context?.connections.length ?? '…' }})</option>
        <option v-for="c in props.context?.connections ?? []" :key="c.id" :value="c.id">
          {{ c.name }} · {{ c.account_id }}{{ c.enabled ? '' : ' (disabled)' }}
        </option>
      </select>
    </div>
    <div class="right">
      <span class="sub">
        Showing data as of <b class="strong">{{ dataThrough ? longDate(dataThrough) : '…' }}</b>
      </span>
      <div class="runs">
        <span v-for="r in lastRuns" :key="r.tool" class="run" :title="r.latest ? `Finished ${utc(r.latest.finished_at)}` : 'No run yet'">
          <ToolChip :tool="r.tool" />
          <template v-if="r.latest">
            <StatusBadge v-if="r.troubled.length" :status="r.troubled[0]?.status ?? 'failed'" />
            {{ relative(r.latest.finished_at) }}
          </template>
          <template v-else>not run yet</template>
        </span>
      </div>
    </div>
  </section>
</template>

<style scoped>
.bar {
  padding: var(--s-14) var(--s-16);
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-14) var(--s-16);
  align-items: flex-end;
}

.select {
  min-width: 200px;
}

.provider {
  display: flex;
  align-items: center;
  gap: var(--s-10);
}

.provider .select {
  min-width: 110px;
  width: auto;
}

.right {
  margin-left: auto;
  display: flex;
  flex-direction: column;
  gap: var(--s-6);
  align-items: flex-end;
}

.strong {
  color: var(--text);
  font-weight: 600;
}

.runs {
  display: flex;
  gap: var(--s-8) var(--s-12);
  flex-wrap: wrap;
  justify-content: flex-end;
}

.run {
  display: inline-flex;
  gap: var(--s-6);
  align-items: center;
  font-size: 11px;
  color: var(--text-2);
}

@media (max-width: 900px) {
  .right {
    margin-left: 0;
    align-items: flex-start;
  }

  .runs {
    justify-content: flex-start;
  }
}
</style>
