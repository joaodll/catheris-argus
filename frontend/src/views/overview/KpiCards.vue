<script setup lang="ts">
import { computed } from 'vue'
import type { Schemas } from '@/api/client'
import AppIcon from '@/components/AppIcon.vue'
import ToolChip from '@/components/ToolChip.vue'
import { decimal, int, scoreColor } from '@/format'
import { failedFindings, resources, threatScore } from './drill'

const props = defineProps<{ data: Schemas['Overview'] | null; connectionCount: number; connectionId: number }>()

const cards = computed(() => {
  const k = props.data?.kpis
  if (!k) return []
  const score = k.threatscore.value
  return [
    {
      tool: 'steampipe',
      label: 'Monitored assets',
      value: int(k.assets.value),
      tone: 'var(--border-control)',
      color: 'var(--text)',
      context: `Across ${props.connectionCount} connection${props.connectionCount === 1 ? '' : 's'}`,
      meter: null,
      to: resources(props.connectionId),
      drill: 'Show in Resources',
    },
    {
      tool: 'prowler',
      label: 'ThreatScore',
      value: decimal(score),
      tone: scoreColor(score),
      color: scoreColor(score),
      context: `Prowler ThreatScore framework · target ${k.threatscore.target}`,
      meter: score == null ? null : { width: `${Math.min(100, Math.max(0, score))}%`, color: scoreColor(score), target: `${k.threatscore.target}%` },
      to: threatScore(props.connectionId),
      drill: 'Show the framework',
    },
    {
      tool: 'prowler',
      label: 'Open critical findings',
      value: int(k.open_critical.value),
      tone: k.open_critical.value ? 'var(--status-fail)' : 'var(--border-control)',
      color: k.open_critical.value ? 'var(--sev-critical-text)' : 'var(--text)',
      context: 'Failed Prowler checks rated critical',
      meter: null,
      to: failedFindings(props.connectionId, 'critical'),
      drill: 'Show in Misconfigurations',
    },
  ]
})
</script>

<template>
  <!-- The Platform's stat tiles (design-system.md, Card → Stat tile). -->
  <section aria-label="Key metrics" class="stat-grid three">
    <template v-if="cards.length">
      <div v-for="c in cards" :key="c.label" class="stat-card kpi" :style="{ '--tone': c.tone }">
        <div class="stat-label"><span>{{ c.label }}</span><ToolChip :tool="c.tool" /></div>
        <b class="stat-value" :style="{ color: c.color }">{{ c.value }}</b>
        <div v-if="c.meter" class="meter mark-track" role="img" :aria-label="`ThreatScore ${c.value} of 100, target ${c.meter.target}`">
          <div class="fill mark-bar" :style="{ width: c.meter.width, '--series': c.meter.color }"></div>
          <span class="target" :style="{ left: c.meter.target }" title="Target"></span>
        </div>
        <span class="stat-sub">{{ c.context }}</span>
        <RouterLink class="drill-link" :to="c.to" :aria-label="`${c.label}: ${c.value}. ${c.drill}`">
          {{ c.drill }}<AppIcon name="chevron" :size="14" :stroke="2" />
        </RouterLink>
      </div>
    </template>
    <template v-else>
      <div v-for="n in 3" :key="n" class="stat-card skeleton"></div>
    </template>
  </section>
</template>

<style scoped>
/* Three tiles fill the row. Below the grid's four-column step it has two columns, so the last
   tile takes the whole second row; on a phone they stack. */
@media (min-width: 1151px) {
  .three {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (min-width: 601px) and (max-width: 1150px) {
  .three > :last-child {
    grid-column: 1 / -1;
  }
}

.kpi {
  gap: var(--s-4);
}

.drill-link {
  margin-top: var(--s-8);
  align-self: flex-start;
}

.meter {
  position: relative;
  height: 6px;
  margin: var(--s-6) 0 var(--s-4);
  border-radius: 3px;
}

.fill {
  height: 100%;
  border-radius: 3px;
}

.target {
  position: absolute;
  top: -3px;
  width: 2px;
  height: 12px;
  background: var(--text);
}
</style>
