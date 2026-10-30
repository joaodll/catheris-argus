<script setup lang="ts">
/**
 * How sure Argus is of an attack path or one of its steps (ADR-0037): Confirmed, Supported,
 * Candidate, Unknown or Blocked (a latent path), an icon and a word (never colour alone). `why` explains a step's level;
 * without it the badge says what the level means in general.
 */
import { computed } from 'vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { CONFIDENCE_MEANING, type Confidence } from './confidence'

const props = defineProps<{ level: Confidence; why?: string }>()
const text = computed(() => props.why ?? CONFIDENCE_MEANING[props.level])
</script>

<template>
  <span class="confidence" :title="text">
    <StatusBadge :status="`conf_${level}`" />
    <span class="sr-only">{{ text }}</span>
  </span>
</template>

<style scoped>
.confidence {
  display: inline-flex;
}
</style>
