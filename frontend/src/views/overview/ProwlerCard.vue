<script setup lang="ts">
import type { Schemas } from '@/api/client'
import ToolChip from '@/components/ToolChip.vue'
import { longDate } from '@/format'
import CheckResults from './CheckResults.vue'
import FailedBySeverity from './FailedBySeverity.vue'
import MonthTable from './MonthTable.vue'
import SeverityTrend from './SeverityTrend.vue'

defineProps<{ data: Schemas['Overview'] | null; range: '6M' | '3M' | '1M'; connectionId: number }>()
const emit = defineEmits<{ selectRange: [range: '6M' | '3M' | '1M'] }>()
</script>

<template>
  <section class="card stack prowler" aria-labelledby="pa-h">
    <div class="card-head">
      <div class="titles">
        <div class="title-row"><ToolChip tool="prowler" /><h2 id="pa-h" class="h2">Check results and failed findings</h2></div>
        <span class="sub">as of {{ data?.data_through ? longDate(data.data_through) : '…' }}</span>
      </div>
    </div>
    <div class="two">
      <CheckResults :data="data" />
      <FailedBySeverity :data="data" :connection-id="connectionId" />
    </div>
    <div class="divided">
      <SeverityTrend :data="data" :range="range" @select-range="(r) => emit('selectRange', r)" />
      <MonthTable :data="data" />
    </div>
  </section>
</template>

<style scoped>
.prowler {
  gap: 18px;
}

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

.two {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: var(--s-28);
}

.divided {
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
  padding-top: 18px;
  border-top: 1px solid var(--border);
}

@media (max-width: 1150px) {
  .two {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
