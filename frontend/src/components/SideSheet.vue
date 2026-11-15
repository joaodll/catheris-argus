<script setup lang="ts">
/**
 * The side panel for details read next to a list: a finding, a resource, a node of the map
 * (design-system.md, Sheet). Forms open in AppModal since 2026-10-13. A native modal <dialog>:
 * the browser traps focus, makes the page inert, closes on Esc and returns focus to the opener.
 * Its title takes focus on open, and again when it shows another record (a connected resource).
 */
import { nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ title: string; description?: string }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement | null>(null)
const titleId = useId()
const descId = useId()
const heading = ref<HTMLElement | null>(null)

function focusTitle(): void {
  void nextTick(() => heading.value?.focus())
}

onMounted(() => {
  dialog.value?.showModal()
  focusTitle()
})
watch(() => props.title, focusTitle)
// Removed while open (closed by Back): close it first, so focus returns to the element that
// opened it.
onBeforeUnmount(() => {
  if (dialog.value?.open) dialog.value.close()
})

function close(): void {
  dialog.value?.close()
  emit('close')
}

function onCancel(event: Event): void {
  event.preventDefault()
  close()
}
</script>

<template>
  <dialog ref="dialog" class="sheet" :aria-labelledby="titleId" :aria-describedby="props.description ? descId : undefined" @cancel="onCancel">
    <header class="head">
      <div class="titles">
        <h2 :id="titleId" ref="heading" class="title" tabindex="-1">{{ props.title }}</h2>
        <p v-if="props.description" :id="descId" class="cap">{{ props.description }}</p>
      </div>
      <button type="button" class="icon-btn" aria-label="Close" @click="close">
        <AppIcon name="cross" :size="16" :stroke="2" />
      </button>
    </header>
    <div class="body"><slot /></div>
  </dialog>
</template>

<style scoped>
.sheet {
  position: fixed;
  inset: 0 0 0 auto;
  width: 640px;
  max-width: 100%;
  height: 100%;
  max-height: none;
  margin: 0;
  padding: 0;
  border: 0;
  border-left: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  box-shadow: var(--shadow-sheet);
  display: flex;
  flex-direction: column;
}

.title {
  overflow-wrap: anywhere;
}

.sheet:not([open]) {
  display: none;
}

.sheet::backdrop {
  background: rgb(0 0 0 / 60%);
  backdrop-filter: blur(2px);
}

.sheet[open] {
  animation: slide 200ms ease-out;
}

@keyframes slide {
  from {
    transform: translateX(24px);
    opacity: 0;
  }
}

.head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--s-12);
  padding: var(--s-18) var(--s-22);
  border-bottom: 1px solid var(--border);
}

.titles {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.titles p {
  margin: 0;
}

.title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
}

.title:focus {
  outline: none;
}

.body {
  flex: 1;
  overflow: auto;
  padding: var(--s-22);
  display: flex;
  flex-direction: column;
  gap: var(--s-24);
}

@media (max-width: 900px) {
  .sheet {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .sheet[open] {
    animation: none;
  }
}
</style>
