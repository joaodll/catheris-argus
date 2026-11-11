<script setup lang="ts">
/**
 * Month over month (palace spec frontend/3ddb7553): each severity's open count at each month's
 * end, the total, and the change from the column before, all from the server (MonthRow). Shared
 * by the Overview's Prowler and vulnerabilities cards and the Vulnerabilities summary. A month
 * with no data shows "—", never 0. Fits its panel at any width: no sideways scroll.
 */
import type { Schemas } from '@/api/client'
import { int, monthName, signed } from '@/format'
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, type Severity } from '@/views/overview/severity'

withDefaults(
  defineProps<{
    rows: Schemas['MonthRow'][]
    caption: string
    noun: string
    what: string
    heading?: boolean
  }>(),
  { heading: true },
)

const SHORT: Record<Severity, string> = { critical: 'Crit', high: 'High', medium: 'Med', low: 'Low', informational: 'Info' }

function change(value: number | null | undefined): { text: string; color: string; sign: string } | null {
  if (value == null) return null
  if (value === 0) return { text: '±0', color: 'var(--text-3)', sign: '' }
  return value > 0
    ? { text: signed(value), color: 'var(--delta-worse)', sign: '▲' }
    : { text: signed(value), color: 'var(--delta-better)', sign: '▼' }
}

const noData = (m: Schemas['MonthRow']) => m.total == null
</script>

<template>
  <div class="mom" :class="{ bare: !heading }">
    <div class="head">
      <span v-if="heading" class="lbl">Month over month</span>
      <span class="sub">{{ what }} · <span class="worse">▲ more {{ noun }}</span> · <span class="better">▼ fewer {{ noun }}</span></span>
    </div>
    <table v-if="rows.length" class="grid">
      <caption class="sr-only">{{ caption }}</caption>
      <thead>
        <tr>
          <th scope="col" class="first">Severity</th>
          <th v-for="m in rows" :key="m.month" scope="col">
            {{ monthName(m.month) }}<span v-if="noData(m)" class="nd">no data</span>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="s in SEVERITIES" :key="s">
          <th scope="row" class="first">
            <span class="dot mark-dot" :style="{ '--series': SEVERITY_COLOR[s] }"></span><span class="long">{{ SEVERITY_LABEL[s] }}</span><span class="short" aria-hidden="true">{{ SHORT[s] }}</span>
          </th>
          <td v-for="m in rows" :key="m.month">
            <template v-if="noData(m)"><span class="none" aria-hidden="true">—</span><span class="sr-only">No data</span></template>
            <template v-else>
              <b class="mono">{{ int(m.values[s]) }}</b>
              <span v-if="change(m.change?.[s])" class="mono d" :style="{ color: change(m.change?.[s])?.color }">{{ change(m.change?.[s])?.sign }}{{ change(m.change?.[s])?.text }}</span>
            </template>
          </td>
        </tr>
        <tr class="total">
          <th scope="row" class="first">Total</th>
          <td v-for="m in rows" :key="m.month">
            <template v-if="noData(m)"><span class="none" aria-hidden="true">—</span><span class="sr-only">No data</span></template>
            <template v-else>
              <b class="mono">{{ int(m.total) }}</b>
              <span v-if="change(m.total_change)" class="mono d" :style="{ color: change(m.total_change)?.color }">{{ change(m.total_change)?.sign }}{{ change(m.total_change)?.text }}</span>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else class="cap">No month-end history yet.</p>
  </div>
</template>

<style scoped>
.mom {
  container-type: inline-size;
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding-top: var(--s-14);
  border-top: 1px solid var(--border);
}

.mom.bare {
  padding-top: 0;
  border-top: 0;
}

.head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: var(--s-12);
  flex-wrap: wrap;
}

.worse {
  color: var(--delta-worse);
}

.better {
  color: var(--delta-better);
}

.grid {
  width: 100%;
  table-layout: fixed;
  border-collapse: collapse;
}

.grid th,
.grid td {
  padding: 4px 3px;
  height: 36px;
  text-align: center;
  font-weight: 400;
}

.grid thead th {
  height: auto;
  padding: 6px 3px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  font-weight: 600;
  color: var(--text-chip);
}

.grid thead th.first {
  font-size: 11px;
  font-weight: 400;
  color: var(--text-3);
}

.nd {
  display: block;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-3);
}

.grid tbody tr {
  border-bottom: 1px solid var(--tile-border);
}

.first {
  width: 140px;
  text-align: left !important;
  font-size: 13px;
  white-space: nowrap;
}

.first .dot {
  margin-right: var(--s-8);
}

.short {
  display: none;
}

td b {
  font-size: 13px;
  font-weight: 600;
}

/* Inline after the value; wraps below it when the column is narrow, never clipped. */
.d {
  display: inline-block;
  margin-left: 6px;
  font-size: 11px;
  white-space: nowrap;
}

.none {
  color: var(--text-3);
}

.total {
  border-top: 1px solid var(--border-strong);
}

.total th {
  font-weight: 600 !important;
}

@container (max-width: 520px) {
  .first {
    width: 64px;
  }

  .first .dot {
    margin-right: var(--s-4);
  }

  .long {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }

  .short {
    display: inline;
  }

  .d {
    margin-left: 0;
  }
}
</style>
