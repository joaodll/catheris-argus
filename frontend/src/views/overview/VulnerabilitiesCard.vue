<script setup lang="ts">
/**
 * Open vulnerabilities, month over month, all types together (owner's decision 2026-11-09;
 * palace spec frontend/3ddb7553). Each account counts as of its latest vulnerabilities scan on or
 * before each month's end. The Vulnerabilities summary has the same table per resource type.
 */
import type { Schemas } from '@/api/client'
import AppIcon from '@/components/AppIcon.vue'
import MonthTable from '@/components/charts/MonthTable.vue'
import ToolChip from '@/components/ToolChip.vue'
import { longDate } from '@/format'
import { vulnerabilitiesSummary } from './drill'

defineProps<{ data: Schemas['Overview'] | null; connectionId: number }>()
</script>

<template>
  <section class="card stack" aria-labelledby="vm-h">
    <div class="card-head">
      <div class="titles">
        <div class="title-row"><ToolChip tool="vulnerabilities" /><h2 id="vm-h" class="h2">Open vulnerabilities, month over month</h2></div>
        <span v-if="!data || data.vulnerabilities" class="sub">as of {{ data?.vulnerabilities ? longDate(data.vulnerabilities.data_through) : '…' }}</span>
      </div>
      <RouterLink v-if="data?.vulnerabilities" class="drill-link" :to="vulnerabilitiesSummary(connectionId)">
        Open the summary<AppIcon name="chevron" :size="14" :stroke="2" />
      </RouterLink>
    </div>
    <div v-if="!data" class="loading" aria-busy="true">
      <div v-for="n in 3" :key="n" class="skeleton sk-row"></div>
    </div>
    <MonthTable
      v-else-if="data.vulnerabilities"
      :rows="data.vulnerabilities.all"
      :heading="false"
      caption="Open vulnerabilities by severity at each month end"
      noun="vulnerabilities"
      what="Open vulnerabilities at each month's end, and the change from the month before"
    />
    <p v-else class="cap">No vulnerabilities scan yet for this selection.</p>
  </section>
</template>

<style scoped>
.titles {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.title-row {
  display: flex;
  gap: var(--s-10);
  align-items: center;
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.sk-row {
  height: 32px;
}

p {
  margin: 0;
}
</style>
