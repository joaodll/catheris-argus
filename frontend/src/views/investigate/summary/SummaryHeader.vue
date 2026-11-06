<script setup lang="ts">
/**
 * The head of every Investigate summary (spec in the palace, frontend/0064ccbd): the Account
 * picker, the day the numbers reflect, what they count (the default slot) and the one severity
 * legend every chart below shares.
 */
import type { Schemas } from '@/api/client'
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL } from '@/views/overview/severity'

defineProps<{
  idPrefix: string
  connectionId: number
  connections: Schemas['ConnectionOut'][] | null
  dataThrough: string | null | undefined
  loaded: boolean
}>()
const emit = defineEmits<{ selectConnection: [id: number] }>()
</script>

<template>
  <div class="head">
    <div class="field">
      <label class="lbl" :for="`${idPrefix}-account`">Account</label>
      <select :id="`${idPrefix}-account`" class="select account" :value="String(connectionId)" @change="emit('selectConnection', Number(($event.target as HTMLSelectElement).value))">
        <option value="0">All connections</option>
        <option v-for="c in connections ?? []" :key="c.id" :value="String(c.id)">{{ c.name }}</option>
      </select>
    </div>
    <span class="through">
      <template v-if="dataThrough">Data through <span class="mono strong">{{ dataThrough }}</span></template>
      <template v-else-if="loaded">No scan yet</template>
    </span>
  </div>
  <p class="cap scope"><slot /></p>
  <ul class="legend" aria-label="Severity colours">
    <li v-for="s in SEVERITIES" :key="s"><span class="dot mark-dot" :style="{ '--series': SEVERITY_COLOR[s] }" aria-hidden="true"></span>{{ SEVERITY_LABEL[s] }}</li>
  </ul>
</template>

<style scoped>
.head {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: var(--s-12);
}

.account {
  min-width: 220px;
}

.through {
  margin-left: auto;
  font-size: 12px;
  color: var(--text-3);
}

.strong {
  color: var(--text);
}

.scope {
  margin: 0;
  max-width: 90ch;
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-14);
  margin: 0;
  padding: 0;
  list-style: none;
  font-size: 12px;
  color: var(--text-2);
}

.legend li {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.legend .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
</style>
