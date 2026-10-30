<script setup lang="ts">
/**
 * CloudFox's loot commands for a resource (ADR-0038; docs/ui/screens.md, E8 Commands block).
 * Shown on a finding's detail and the resource sheet. Argus never runs these; there is no run
 * control here, and none exists anywhere. Grouped by label, read-only checks first, the ones
 * that act on the target last and drawn as a warning.
 */
import { computed, useId } from 'vue'
import type { Schemas } from '@/api/client'
import CopyButton from '@/components/CopyButton.vue'

type Command = Schemas['CommandOut']
type Label = Command['label']

const props = defineProps<{ commands: Command[] }>()
const headingId = useId()

const GROUPS: { label: Label; title: string; tone: string }[] = [
  { label: 'check', title: 'Check', tone: 'ok' },
  { label: 'reads_data', title: 'Reads data', tone: 'warn' },
  { label: 'acts_on_target', title: 'Acts on the target — run only with authorization', tone: 'fail' },
]

const groups = computed(() =>
  GROUPS.map((g) => ({ ...g, items: props.commands.filter((c) => c.label === g.label) })).filter((g) => g.items.length),
)
</script>

<template>
  <section v-if="commands.length" class="block commands" :aria-labelledby="headingId">
    <h3 :id="headingId" class="lbl">Commands (CloudFox)</h3>
    <p class="warn-line">Argus never runs these. Run them only with written authorization.</p>
    <div v-for="g in groups" :key="g.label" class="group" :class="`tone-${g.tone}`">
      <h4 class="group-head"><span class="dot" aria-hidden="true"></span>{{ g.title }}</h4>
      <div v-for="(c, i) in g.items" :key="`${g.label}-${i}`" class="cmd" :class="{ acts: g.label === 'acts_on_target' }">
        <p v-if="c.note" class="note">{{ c.note }}</p>
        <div class="cmd-row">
          <pre class="code" tabindex="0" :aria-label="`${g.title} command from ${c.source}`">{{ c.command }}</pre>
          <CopyButton :value="c.command" :label="`Copy the ${g.title} command`" />
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.commands {
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
}

.warn-line {
  margin: 0;
  font-size: 12px;
  color: var(--text-2);
}

.group {
  display: flex;
  flex-direction: column;
  gap: var(--s-6);
}

.group-head {
  display: flex;
  align-items: center;
  gap: var(--s-6);
  margin: var(--s-6) 0 0;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-2);
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.tone-ok .dot {
  background: var(--status-ok);
}

.tone-warn .dot {
  background: var(--status-warn);
}

.tone-fail .group-head {
  color: var(--status-fail);
}

.tone-fail .dot {
  background: var(--status-fail);
}

.note {
  margin: 0 0 2px;
  font-size: 11px;
  color: var(--text-3);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.cmd-row {
  display: flex;
  align-items: flex-start;
  gap: var(--s-8);
}

.code {
  flex: 1;
  min-width: 0;
  margin: 0;
  padding: var(--s-8) var(--s-10);
  background: var(--surface-sunken);
  border: 1px solid var(--border);
  border-radius: var(--r-control);
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

/* A command that acts on the target: a warning edge, never a run affordance. */
.cmd.acts .code {
  border-color: color-mix(in srgb, var(--status-fail) 45%, var(--border));
  background: color-mix(in srgb, var(--status-fail) 6%, var(--surface-sunken));
}
</style>
