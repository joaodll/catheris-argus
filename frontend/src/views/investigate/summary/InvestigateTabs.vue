<script setup lang="ts">
/**
 * Summary | List under an Investigate screen's title (owner's decision 2026-11-05; spec in the
 * palace, frontend/0064ccbd): the underline tabs (UnderlineTabs) with this pair. The view owns
 * the panels (ids `<idPrefix>-summary` and `<idPrefix>-list`) and the URL.
 */
import UnderlineTabs from '@/components/UnderlineTabs.vue'
import type { Tab } from './summaryTab'

defineProps<{ modelValue: Tab; label: string; idPrefix: string }>()
const emit = defineEmits<{ 'update:modelValue': [tab: Tab] }>()
const TABS = [
  { value: 'summary', label: 'Summary' },
  { value: 'list', label: 'List' },
] as const
</script>

<template>
  <UnderlineTabs :model-value="modelValue" :tabs="TABS" :label="label" :id-prefix="idPrefix" @update:model-value="(t) => emit('update:modelValue', t)" />
</template>
