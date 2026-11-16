<script setup lang="ts">
/**
 * One step's evidence and fix (spec W6 §3.3, §10): the route page shows it under a link's
 * "Evidence and fix" and under a foothold or a login, and the Map's Attack Path view under its
 * current step (§11.5). One component, so the two never say different things. Cloud names are
 * text, never markup.
 */
import { computed } from 'vue'
import DoorEvidence from '../DoorEvidence.vue'
import { doorOfEdge, doorWhy } from '../doorWhy'
import { LEVEL_LABEL, type StepLevel } from './routeClass'
import { breakLink, factsOf, footholdCve, moveWords, reasonLine, type StepOut } from './routeWords'

const props = defineProps<{ step: StepOut }>()

const level = computed(() => LEVEL_LABEL[props.step.level as StepLevel] ?? props.step.level)
// A walk-made step (a foothold, a login) stands on one resource: no move, no door.
const self = computed(() => props.step.source.uid === props.step.target.uid)
const opened = computed(() => {
  if (self.value) return null
  const step = props.step
  const door = step.source.uid === 'internet' ? doorOfEdge(step) : null
  return { move: moveWords(step), door, doorLine: door ? doorWhy(door) : null, facts: factsOf(step), fix: breakLink(step) }
})
const cve = computed(() => footholdCve(props.step))
</script>

<template>
  <template v-if="self">
    <span class="reason">
      {{ reasonLine(step) }}
      <RouterLink v-if="cve && step.target.resource_id != null" :to="{ name: 'vulnerabilities', query: { q: cve, resource: String(step.target.resource_id) } }">See it in Vulnerabilities</RouterLink>
    </span>
    <span class="small">Fix: {{ breakLink(step) }}</span>
  </template>
  <div v-else-if="opened" class="break">
    <p class="sentence">{{ opened.move.sentence }}</p>
    <p class="body"><span class="level">{{ level }}</span> {{ reasonLine(step) }}</p>
    <template v-if="opened.door">
      <p v-if="opened.doorLine" class="body">{{ opened.doorLine }}</p>
      <DoorEvidence v-if="opened.door.network.length || opened.door.state" :network="opened.door.network" :state="opened.door.state" />
    </template>
    <dl v-if="opened.facts.length || step.day" class="attrs">
      <div v-if="step.day"><dt class="lbl">Seen</dt><dd class="mono">{{ step.day }}</dd></div>
      <div v-for="f in opened.facts" :key="f.label">
        <dt class="lbl">{{ f.label }}</dt>
        <dd :class="{ mono: f.mono }" :title="f.title">{{ f.value }}</dd>
      </div>
    </dl>
    <p class="body"><strong>Break this link:</strong> {{ opened.fix }}</p>
    <details class="tech">
      <summary>Technical details</summary>
      <dl class="attrs">
        <div><dt class="lbl">Link type</dt><dd class="mono">{{ step.type }}</dd></div>
        <div><dt class="lbl">Source</dt><dd class="mono">{{ step.origin }}</dd></div>
        <div><dt class="lbl">Reason</dt><dd class="mono">{{ step.reason }}</dd></div>
      </dl>
    </details>
  </div>
</template>

<style scoped>
.reason {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-4) var(--s-8);
  font-size: 12px;
  color: var(--text-2);
}

.small {
  font-size: 12px;
  color: var(--text-2);
  overflow-wrap: anywhere;
}

.body {
  font-size: 13px;
  line-height: 1.55;
  max-width: 80ch;
}

/* A step's level: the word only, small caps, so it is never read as the route's class badge. */
.level {
  font-size: 11px;
  font-weight: 600;
  font-variant: all-small-caps;
  letter-spacing: 0.04em;
  color: var(--text-2);
}

.break {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  padding: var(--s-12) var(--s-14);
  background: var(--surface-sunken);
  border-radius: var(--r-tile);
}

.break p {
  margin: 0;
}

.sentence {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}

.attrs {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: var(--s-8) var(--s-16);
  font-size: 12px;
}

.attrs dd {
  margin: 2px 0 0;
  overflow-wrap: anywhere;
}

.tech summary {
  cursor: pointer;
  font-size: 12px;
  color: var(--text-3);
}

.tech summary:hover {
  color: var(--link);
}

.tech .attrs {
  margin-top: var(--s-8);
}
</style>
