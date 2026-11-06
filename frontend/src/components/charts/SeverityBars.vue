<script setup lang="ts">
/**
 * One bar per item, split into its severities (spec: palace frontend/0064ccbd, "SeverityBars"):
 * the Investigate summaries' accounts, categories, services, regions, reach and top checks.
 * A list, not a table. The item's name is the one link (a 12 px segment can't be a 24 px
 * target); its accessible name carries all five counts, and the sub-line names critical and high
 * in words, so no severity is told by colour alone. Widths share one scale: the largest item.
 *
 * Plain counts (the Resources summary's accounts, regions and services: assets have no
 * severity) leave `severities` out and give the bars one `series` colour; the name then carries
 * the count alone.
 */
import { computed } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import SeverityTag from '@/components/SeverityTag.vue'
import { int } from '@/format'
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_TEXT, type Severity } from '@/views/overview/severity'

export interface SeverityBarItem {
  key: string
  label: string
  severities?: Record<Severity, number> // absent: a plain count, drawn in the `series` colour
  total: number
  to: RouteLocationRaw | null // null: nothing in the list reproduces it (no category)
  mono?: boolean // an id or slug (a service, a region)
  muted?: boolean // "No category": a placeholder, not a name
  dot?: string // a colour mark before the name (an account's provider)
  tag?: Severity // a severity tag before the name (a check: one severity)
  sub?: string // replaces the critical and high line (a check's id and accounts)
}

// `wrap`: long names (a check's title) take two lines and a wider column instead of an ellipsis.
const props = defineProps<{ items: SeverityBarItem[]; noun?: string; wrap?: boolean; series?: string }>()

const max = computed(() => Math.max(1, ...props.items.map((i) => i.total)))
const rows = computed(() =>
  props.items.map((item) => {
    const width = `${(item.total / max.value) * 100}%`
    const counts = item.severities
    if (!counts) {
      return {
        ...item,
        width,
        plain: true,
        segments: item.total ? [{ severity: 'all', grow: item.total, color: props.series ?? 'var(--text-3)' }] : [],
        words: [],
        name: `${item.label}: ${int(item.total)} ${props.noun ?? 'open'}.`,
      }
    }
    const shown = SEVERITIES.filter((s) => counts[s] > 0)
    return {
      ...item,
      width,
      plain: false,
      segments: shown.map((s) => ({ severity: s, grow: counts[s], color: SEVERITY_COLOR[s] })),
      words: (['critical', 'high'] as Severity[]).filter((s) => counts[s] > 0).map((s) => ({ s, text: `${int(counts[s])} ${s}` })),
      name: `${item.label}: ${int(item.total)} ${props.noun ?? 'open'}: ${SEVERITIES.map((s) => `${int(counts[s])} ${SEVERITY_LABEL[s].toLowerCase()}`).join(', ')}.`,
    }
  }),
)
</script>

<template>
  <ol class="bars" :class="{ wrap }">
    <li v-for="r in rows" :key="r.key" class="row">
      <div class="who">
        <span class="name-line">
          <span v-if="r.dot" class="dot mark-dot" :style="{ '--series': r.dot }" aria-hidden="true"></span>
          <SeverityTag v-if="r.tag" :severity="r.tag" compact />
          <RouterLink v-if="r.to" class="name" :class="{ mono: r.mono, placeholder: r.muted }" :to="r.to" :title="r.label">
            {{ r.label }}<span class="sr-only"> — {{ r.name }} Show in list.</span>
          </RouterLink>
          <span v-else class="name" :class="{ mono: r.mono, placeholder: r.muted }" :title="r.label">
            {{ r.label }}<span class="sr-only"> — {{ r.name }}</span>
          </span>
        </span>
        <span v-if="!r.plain || r.sub" class="sub">
          <template v-if="r.sub">{{ r.sub }}</template>
          <template v-else-if="r.words.length">
            <template v-for="(w, i) in r.words" :key="w.s"><template v-if="i"> · </template><span class="mono" :style="{ color: SEVERITY_TEXT[w.s] }">{{ w.text }}</span></template>
          </template>
          <template v-else>No critical or high</template>
        </span>
      </div>
      <span class="track mark-track" aria-hidden="true">
        <span class="fill" :style="{ width: r.width }">
          <span
            v-for="seg in r.segments"
            :key="seg.severity"
            class="seg mark-bar"
            :style="{ flexGrow: seg.grow, '--series': seg.color }"
          ></span>
        </span>
      </span>
      <span class="count mono" aria-hidden="true">{{ int(r.total) }}</span>
    </li>
  </ol>
</template>

<style scoped>
.bars {
  display: flex;
  flex-direction: column;
  margin: 0;
  padding: 0;
  list-style: none;
}

.row {
  display: grid;
  grid-template-columns: minmax(120px, 34%) 1fr 64px;
  align-items: center;
  gap: var(--s-12);
  min-height: 44px;
  padding: var(--s-4) var(--s-6);
  border-radius: var(--r-control);
}

.row:hover {
  background: var(--surface-raised);
}

.who {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.name-line {
  display: flex;
  align-items: center;
  gap: var(--s-8);
  min-width: 0;
}

.name {
  overflow: hidden;
  font-size: 13px;
  color: var(--text);
  text-overflow: ellipsis;
  white-space: nowrap;
}

a.name:hover {
  color: var(--link-hover);
}

.placeholder {
  font-style: italic;
  color: var(--text-2);
}

.dot {
  flex-shrink: 0;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.sub {
  overflow: hidden;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.track {
  display: block;
  height: 12px;
  border-radius: 4px;
}

.fill {
  display: flex;
  gap: 1px;
  height: 100%;
}

.seg {
  min-width: 2px;
  height: 100%;
}

.seg:first-child {
  border-radius: 4px 0 0 4px;
}

.seg:last-child {
  border-radius: 0 4px 4px 0;
}

.seg:only-child {
  border-radius: 4px;
}

.count {
  font-size: 15px;
  font-weight: 600;
  text-align: right;
  color: var(--text);
}

.wrap .row {
  grid-template-columns: minmax(160px, 52%) 1fr 48px;
}

.wrap .name-line {
  align-items: flex-start;
}

.wrap .name {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  white-space: normal;
}

@container (max-width: 520px) {
  .row {
    grid-template-columns: minmax(96px, 40%) 1fr 56px;
  }

  .sub {
    white-space: normal;
  }
}
</style>
