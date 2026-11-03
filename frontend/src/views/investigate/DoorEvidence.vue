<script setup lang="ts">
/**
 * What a door is judged from (ADR-0035, fifth amendment): the instance's state, then per network
 * interface what is public and open, and each subnet's route and network ACL. Words only, ids in
 * mono: the verdict never rests on colour.
 */
import { interfaceTitle, openWords, stateWord, subnetWords, type DoorInterface } from './doorEvidence'

defineProps<{ network: DoorInterface[]; state?: string | null }>()
</script>

<template>
  <div class="evidence">
    <p v-if="state && state !== 'running'" class="line">Instance {{ stateWord(state).toLowerCase() }}: nothing listens until it runs.</p>
    <section v-for="(n, i) in network" :key="n.interface ?? i" class="iface" :aria-label="interfaceTitle(n)">
      <p class="title mono">{{ interfaceTitle(n) }}</p>
      <p class="line">Open to the internet: <span class="mono">{{ openWords(n) }}</span></p>
      <ul v-if="n.subnets.length" class="subnets">
        <li v-for="s in n.subnets" :key="`${s.subnet}|${s.family}`" class="mono">{{ subnetWords(s) }}</li>
      </ul>
      <p v-else class="line">No subnet recorded.</p>
    </section>
  </div>
</template>

<style scoped>
.evidence {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  font-size: 12px;
  color: var(--text-2);
  min-width: 0;
}

.iface {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  min-width: 0;
}

.title {
  margin: 0;
  color: var(--text);
  overflow-wrap: anywhere;
}

.line {
  margin: 0;
  overflow-wrap: anywhere;
}

.subnets {
  margin: 0;
  padding-left: var(--s-16);
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  overflow-wrap: anywhere;
}
</style>
