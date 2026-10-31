<script setup lang="ts">
/**
 * The Overview's 6-month strip (docs/ui/screens.md, "ThreatScore strip: choosing the
 * framework"): the ThreatScore by default, or any framework with results for the connection,
 * chosen in the select (2026-10-15). The ThreatScore is Prowler's weighted score and comes with
 * the Overview; a framework is its requirement pass rate, from its own Compliance read.
 */
import { computed } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import AppIcon from '@/components/AppIcon.vue'
import { useResource } from '@/composables/useResource'
import { decimal, deltaColor, monthName, scoreColor, signed } from '@/format'
import { frameworkName, frameworkShortName } from '@/views/posture/compliance'
import { framework as frameworkLink, THREATSCORE_FRAMEWORK } from './drill'

const props = defineProps<{ data: Schemas['Overview'] | null; connectionId: number; framework: string }>()
const emit = defineEmits<{ choose: [key: string] }>()

const frameworks = useResource(
  () => unwrap(api.GET('/api/v1/compliance', { params: { query: { connection_id: props.connectionId, order: 'name_asc', limit: 200 } } })),
  { watch: [() => props.connectionId] },
)
// The ThreatScore is listed once, as the default: its framework's pass rate is left out.
const listed = computed(() =>
  (frameworks.data.value?.items ?? []).filter((f) => f.framework !== THREATSCORE_FRAMEWORK).map((f) => ({ key: f.framework, name: frameworkName(f), short: frameworkShortName(f) })),
)
// A remembered framework with no results for this connection falls back to the ThreatScore,
// once the list says so; while the list loads (or if it failed) the choice stands.
const chosen = computed(() => {
  if (!props.framework || !frameworks.data.value) return props.framework
  return listed.value.some((f) => f.key === props.framework) ? props.framework : ''
})
const options = computed(() =>
  chosen.value && !listed.value.some((f) => f.key === chosen.value) ? [{ key: chosen.value, name: chosen.value, short: chosen.value }, ...listed.value] : listed.value,
)
const name = computed(() => (chosen.value ? (options.value.find((f) => f.key === chosen.value)?.name ?? chosen.value) : 'ThreatScore'))

const detail = useResource(
  async () =>
    chosen.value
      ? unwrap(api.GET('/api/v1/compliance/{framework}', { params: { path: { framework: chosen.value }, query: { connection_id: props.connectionId } } }))
      : null,
  { watch: [chosen, () => props.connectionId] },
)
// The framework's read, only once it is the one chosen (not the previous choice's).
const shown = computed(() => (chosen.value && detail.data.value?.framework === chosen.value ? detail.data.value : null))

const strip = computed(() => (chosen.value ? (shown.value?.month_table ?? []) : (props.data?.threatscore.strip ?? [])))
const first = computed(() => (chosen.value ? shown.value?.change_since : strip.value[0]?.month))
const change = computed(() => (chosen.value ? (shown.value?.change ?? null) : (props.data?.threatscore.change_since_first ?? null)))
// One scored month has no change to show (2026-10-31 review): the framework page's words.
const enoughMonths = computed(() => strip.value.filter((m) => m.score != null).length >= 2)
const loadingFramework = computed(() => Boolean(chosen.value) && !shown.value && !detail.error.value)
const link = computed(() => frameworkLink(props.connectionId, chosen.value || THREATSCORE_FRAMEWORK))
</script>

<template>
  <section class="card strip" aria-labelledby="ts-h">
    <div class="titles">
      <h2 id="ts-h" class="lbl">Score · 6 months</h2>
      <label class="sr-only" for="ts-framework">Framework</label>
      <select id="ts-framework" class="select" :value="chosen" :title="name" @change="emit('choose', ($event.target as HTMLSelectElement).value)">
        <option value="">ThreatScore</option>
        <option v-for="f in options" :key="f.key" :value="f.key" :title="f.name">{{ f.short }}</option>
      </select>
      <span class="what">{{ chosen ? 'Requirements passed ÷ assessed' : "Prowler's weighted score" }}</span>
      <span class="sub">Month-end · current month to date</span>
      <RouterLink class="drill-link" :to="link" :aria-label="`${name}: show the framework`">
        Show the framework<AppIcon name="chevron" :size="14" :stroke="2" />
      </RouterLink>
    </div>
    <div class="scroll">
      <div v-if="chosen && detail.error.value" class="failed">
        <span class="sub">This framework's scores didn't load.</span>
        <button type="button" class="btn btn-secondary btn-sm" @click="detail.reload()">Retry</button>
      </div>
      <div v-else-if="loadingFramework" class="skeleton sk-52"></div>
      <ol v-else-if="strip.length" class="months" :aria-label="`${name} at the end of each month`">
        <li
          v-for="(m, i) in strip"
          :key="m.month"
          class="month"
          :class="{ current: i === strip.length - 1, 'no-glow': m.score == null }"
          :style="{ '--series': scoreColor(m.score) }"
          :title="`${monthName(m.month)}: ${m.score == null ? 'no scan' : decimal(m.score)}${i === strip.length - 1 ? ' (month to date)' : ''}`"
        >
          <span class="m">{{ monthName(m.month) }}</span>
          <b class="mono v">{{ m.score == null ? '—' : decimal(m.score) }}</b>
          <span class="mono d" :style="{ color: m.change == null ? 'var(--text-3)' : deltaColor(m.change, true) }">
            {{ m.change == null ? '·' : signed(m.change, 1) }}
          </span>
        </li>
      </ol>
      <span v-else-if="props.data" class="sub">No ThreatScore yet: it appears after the first Prowler scan.</span>
      <div v-else class="skeleton sk-52"></div>
    </div>
    <div v-if="strip.length && !enoughMonths && !loadingFramework" class="since">
      <span class="sub">Needs two months of history</span>
    </div>
    <div v-else class="since">
      <span class="sub">Since {{ first ? monthName(first) : '…' }}</span>
      <b class="mono total" :style="{ color: deltaColor(change, true) }">{{ change == null ? '—' : `${signed(change, 1)} pts` }}</b>
    </div>
  </section>
</template>

<style scoped>
.strip {
  padding: var(--s-12) var(--s-16);
  display: grid;
  grid-template-columns: 220px minmax(0, 1fr) 110px;
  gap: var(--s-16);
  align-items: center;
}

.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.titles h2 {
  margin: 0;
}

.titles .select {
  width: 100%;
  margin: 2px 0;
}

.what {
  font-size: 12px;
  color: var(--text-2);
}

.failed {
  display: flex;
  align-items: center;
  gap: var(--s-12);
}

.scroll {
  overflow-x: auto;
}

.months {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(6, minmax(64px, 1fr));
  gap: var(--s-6);
  min-width: 420px;
}

.month {
  --glow: color-mix(in srgb, var(--series) var(--glow-mix), transparent);

  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1px;
  padding: 5px 0;
  border-radius: 6px;
  background: var(--tile);
  border: 1px solid var(--tile-border);
  box-shadow: inset 0 -2px 0 var(--series), 0 2px var(--glow-blur) -2px var(--glow);
}

.month.current {
  border-style: dashed;
  border-color: var(--tile-current);
}

.m {
  font-size: 10px;
  color: var(--text-3);
}

.v {
  font-size: 13px;
  font-weight: 600;
}

.d {
  font-size: 10px;
}

.since {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 2px;
}

.total {
  font-size: 18px;
  font-weight: 600;
}

@media (max-width: 900px) {
  .strip {
    grid-template-columns: minmax(0, 1fr);
  }

  .since {
    align-items: flex-start;
  }
}
</style>
