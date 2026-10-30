<script setup lang="ts">
/**
 * Accounts, month over month (screens.md E10, item 4): a compact heatmap, a row per account and
 * a cell per month tinted with its score band, made to be screenshotted for a slide with 30+
 * accounts (2026-10-15). Its eyebrow names the framework and the day, so the card reads alone.
 * Choosing an account switches the page to it. No total or average row (the user set the
 * overall average aside on 2026-10-07).
 */
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppPagination from '@/components/AppPagination.vue'
import ProviderTag from '@/components/ProviderTag.vue'
import { decimal, longDate, monthName, scoreColor } from '@/format'
import { scoreChange } from './compliance'

const props = defineProps<{
  framework: string | null // its name, or the key until Argus has one; null while loading
  provider: string | null
  accounts: Schemas['AccountList'] | null
  error: string | null
  selected: number // 0 = all connections
  page: number
  limit: number
}>()
const emit = defineEmits<{ select: [connectionId: number]; page: [page: number]; retry: [] }>()

const rows = computed(() => props.accounts?.items ?? [])
const months = computed(() => rows.value[0]?.months.map((m) => m.month) ?? [])
const current = computed(() => months.value[months.value.length - 1])
const caption = computed(() => {
  const text = "each account's score at each month end; choose an account to show it above and below"
  return props.framework ? `${props.framework}: ${text}` : text.charAt(0).toUpperCase() + text.slice(1)
})
// The score bands of scoreColor(), named so the colour is never the only signal.
const LEGEND = [
  { label: 'Under 60', score: 0 },
  { label: '60 to 70', score: 60 },
  { label: '70 to 80', score: 70 },
  { label: '80 and over', score: 80 },
]
</script>

<template>
  <section class="card stack" aria-labelledby="accounts-h">
    <div class="fw-line">
      <span class="fw">
        <ProviderTag v-if="props.provider" :provider="props.provider" />
        <span class="fw-name">{{ props.framework }}</span>
      </span>
      <span v-if="props.accounts" class="mono day">{{ props.accounts.data_through ? longDate(props.accounts.data_through) : 'No scan yet' }}</span>
    </div>
    <div class="head">
      <h2 id="accounts-h" class="h2">Accounts, month over month</h2>
      <span class="sub">Score at month end, and change from the month before · <span class="better">▲ higher score</span> · <span class="worse">▼ lower score</span></span>
    </div>
    <ul class="legend" aria-label="Score bands">
      <li v-for="band in LEGEND" :key="band.label"><span class="swatch" :style="{ '--band': scoreColor(band.score) }" aria-hidden="true"></span>{{ band.label }}</li>
    </ul>
    <AlertBanner v-if="props.error" kind="fail">
      Accounts didn't load: {{ props.error }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="emit('retry')">Retry</button></template>
    </AlertBanner>
    <div v-else-if="!props.accounts" aria-busy="true" class="loading"><div v-for="n in 5" :key="n" class="skeleton sk-28"></div></div>
    <p v-else-if="rows.length === 0" class="cap">No account has a score for this framework yet.</p>
    <div v-else class="scroll">
      <table class="grid">
        <caption class="sr-only">{{ caption }}</caption>
        <thead>
          <tr>
            <th scope="col" class="first">Account</th>
            <th v-for="m in months" :key="m" scope="col" :class="{ current: m === current }">{{ monthName(m) }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="a in rows" :key="a.connection_id" :class="{ chosen: a.connection_id === props.selected }">
            <th scope="row" class="first">
              <button type="button" class="account" :aria-pressed="a.connection_id === props.selected" @click="emit('select', a.connection_id)">
                <span class="name" :title="a.connection">{{ a.connection }}</span>
                <span class="mono acct">{{ a.account_id }}</span>
              </button>
            </th>
            <td v-for="m in a.months" :key="m.month">
              <span v-if="m.score != null" class="cell" :style="{ '--band': scoreColor(m.score) }">
                <b class="mono">{{ decimal(m.score) }}</b>
                <span v-if="m.change != null" class="mono d" :style="{ color: scoreChange(m.change).color }" :aria-label="scoreChange(m.change).label">{{ scoreChange(m.change).text }}</span>
              </span>
              <span v-else class="soft" aria-label="No scan">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <AppPagination v-if="rows.length" :total="props.accounts?.total ?? 0" :page="props.page" :limit="props.limit" noun="account" @change="emit('page', $event)" />
  </section>
</template>

<style scoped>
.fw-line {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: var(--s-12);
  flex-wrap: wrap;
  font-size: 13px;
}

.fw {
  display: inline-flex;
  align-items: baseline;
  gap: var(--s-8);
  min-width: 0;
}

.fw-name {
  font-weight: 600;
  color: var(--text);
}

.day {
  font-size: 12px;
  color: var(--text-3);
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-4) var(--s-16);
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

/* The band's tint, bordered in the band so a light tint still shows on the surface. */
.swatch {
  width: 10px;
  height: 10px;
  border: 1px solid var(--band);
  border-radius: 2px;
  background: color-mix(in srgb, var(--band) 16%, transparent);
}

.head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: var(--s-12);
  flex-wrap: wrap;
}

.better {
  color: var(--delta-better);
}

.worse {
  color: var(--delta-worse);
}

.loading {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.scroll {
  overflow-x: auto;
}

.grid {
  width: 100%;
  min-width: 640px;
  border-collapse: collapse;
}

.grid th,
.grid td {
  padding: 2px;
  height: 28px;
  text-align: center;
  font-weight: 400;
  white-space: nowrap;
}

.grid thead th {
  height: auto;
  padding: 6px 3px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  font-weight: 600;
  color: var(--text-chip);
}

.grid thead th.current {
  text-decoration: underline dashed var(--tile-current);
  text-underline-offset: 4px;
}

.grid tbody tr {
  border-bottom: 1px solid var(--tile-border);
}

.first {
  position: sticky;
  left: 0;
  z-index: 1;
  width: 220px;
  max-width: 220px;
  background: var(--surface);
  text-align: left !important;
}

.grid thead th.first {
  font-size: 11px;
  font-weight: 400;
  color: var(--text-3);
}

.chosen {
  background: var(--accent-wash);
}

/* Sticky: the wash is translucent, so it is laid over the surface, or the cells scrolling under
   it would show through. */
.chosen .first {
  background: linear-gradient(var(--accent-wash), var(--accent-wash)), var(--surface);
  box-shadow: inset 2px 0 0 var(--accent);
}

.account {
  display: flex;
  align-items: baseline;
  gap: var(--s-8);
  width: 100%;
  min-height: 24px;
  padding: 2px var(--s-8);
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text);
  text-align: left;
  cursor: pointer;
}

.account:hover .name {
  text-decoration: underline;
}

.name {
  overflow: hidden;
  min-width: 0;
  font-size: 13px;
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.acct {
  flex: none;
  font-size: 11px;
  color: var(--text-3);
}

/* A cell's score band at 16 %: every text on it stays at 4.5:1 or more (contrast.test.ts). */
.cell {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 24px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--band) 16%, transparent);
}

td b {
  font-size: 13px;
  font-weight: 600;
}

.d {
  margin-left: 6px;
  font-size: 11px;
}

.soft {
  color: var(--text-3);
}
</style>
