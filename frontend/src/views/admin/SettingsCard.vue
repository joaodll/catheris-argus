<script setup lang="ts">
/** One settings topic: its own form, Save and Discard, and the unsaved-changes label. A panel
 * (design-system.md, Card → Panel): a header bar, the fields, a footer bar with the actions. */
import { inject, onBeforeUnmount, watch } from 'vue'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import { SETTINGS_SECTIONS } from './settingsSections'

const props = defineProps<{ id: string; title: string; description: string; dirty: boolean; saving: boolean; error: string | null; saveLabel: string }>()
const emit = defineEmits<{ save: []; discard: [] }>()

// The page's "On this page" list shows each card, with a dot while it has unsaved changes.
const sections = inject(SETTINGS_SECTIONS, null)
watch(
  () => [props.title, props.dirty] as const,
  ([title, dirty]) => sections?.set({ id: props.id, title, dirty }),
  { immediate: true },
)
onBeforeUnmount(() => sections?.remove(props.id))
</script>

<template>
  <section class="card panel settings" :aria-labelledby="`${id}-h`">
    <div class="panel-h">
      <div class="titles">
        <div class="title-row">
          <h2 :id="`${id}-h`" class="h2">{{ title }}</h2>
          <span v-if="dirty" class="dirty"><span class="dot-warn" aria-hidden="true"></span>Unsaved changes</span>
        </div>
        <span class="cap">{{ description }}</span>
      </div>
    </div>
    <form :id="id" class="panel-body body" novalidate @submit.prevent="emit('save')">
      <slot />
      <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
    </form>
    <div class="panel-foot actions">
      <button type="button" class="btn btn-secondary" :disabled="!dirty || saving" @click="emit('discard')">Discard</button>
      <button type="submit" :form="id" class="btn btn-primary" :disabled="!dirty || saving">
        <AppIcon v-if="saving" name="spinner" :size="16" :stroke="2.4" />{{ saving ? 'Saving…' : saveLabel }}
      </button>
    </div>
  </section>
</template>

<style scoped>
/* A link from the page's list lands with the title clear of the top edge. */
.settings {
  scroll-margin-top: var(--s-16);
}

.titles {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.title-row {
  display: flex;
  gap: var(--s-10);
  align-items: center;
  flex-wrap: wrap;
}

.dirty {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--status-warn);
}

.dot-warn {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--status-warn);
}

.body {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding-top: var(--s-18);
  padding-bottom: var(--s-18);
}

.actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--s-10);
}
</style>
