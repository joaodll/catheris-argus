<script setup lang="ts">
/**
 * CatherIs Platform's centred modal for create and edit forms (design-system.md, Modal; ADR-0028,
 * fifth amendment). A native modal <dialog>: the browser traps focus, makes the page inert and
 * returns focus to the opener; Esc and the backdrop close it. With unsaved changes (`dirty`),
 * closing asks first with the browser's confirm(), as the Platform does.
 */
import { onBeforeUnmount, onMounted, ref, useId } from 'vue'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ title: string; description?: string; dirty?: boolean; wide?: boolean }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement | null>(null)
const titleId = useId()
const descId = useId()

onMounted(() => dialog.value?.showModal())
onBeforeUnmount(() => {
  if (dialog.value?.open) dialog.value.close()
})

function close(): void {
  dialog.value?.close()
  emit('close')
}

function requestClose(): void {
  if (!props.dirty || window.confirm('Discard your changes? What you entered here is lost.')) close()
}

function onCancel(event: Event): void {
  event.preventDefault()
  requestClose()
}

// A click on the backdrop lands on the <dialog> itself, outside its box.
function onClick(event: MouseEvent): void {
  const el = dialog.value
  if (!el || event.target !== el) return
  const box = el.getBoundingClientRect()
  const inside = event.clientX >= box.left && event.clientX <= box.right && event.clientY >= box.top && event.clientY <= box.bottom
  if (!inside) requestClose()
}

defineExpose({ requestClose })
</script>

<template>
  <dialog
    ref="dialog"
    class="modal"
    :class="{ 'is-wide': props.wide }"
    :aria-labelledby="titleId"
    :aria-describedby="props.description ? descId : undefined"
    @cancel="onCancel"
    @click="onClick"
  >
    <header class="head">
      <div class="titles">
        <h2 :id="titleId" class="title">{{ props.title }}</h2>
        <p v-if="props.description" :id="descId" class="cap">{{ props.description }}</p>
      </div>
      <button type="button" class="icon-btn" aria-label="Close" @click="requestClose">
        <AppIcon name="cross" :size="16" :stroke="2" />
      </button>
    </header>
    <div class="body"><slot /></div>
    <footer class="foot"><slot name="footer" /></footer>
  </dialog>
</template>

<style scoped>
.modal {
  width: min(520px, calc(100vw - 32px));
  max-height: 90vh;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--r-card);
  background: var(--surface);
  color: var(--text);
  box-shadow: var(--shadow-sheet);
  flex-direction: column;
  overflow: hidden;
}

.modal[open] {
  display: flex;
  animation: rise 180ms ease-out;
}

.modal.is-wide {
  width: min(720px, calc(100vw - 32px));
}

.modal::backdrop {
  background: rgb(0 0 0 / 60%);
  backdrop-filter: blur(2px);
}

@keyframes rise {
  from {
    opacity: 0;
    transform: translateY(8px) scale(0.98);
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
  min-width: 0;
}

.titles p {
  margin: 0;
}

.title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.body {
  flex: 1;
  overflow: auto;
  padding: var(--s-22);
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.foot {
  display: flex;
  justify-content: flex-end;
  gap: var(--s-10);
  padding: var(--s-14) var(--s-22);
  border-top: 1px solid var(--border);
}

@media (max-width: 900px) {
  .modal.is-wide {
    width: 100vw;
    max-width: 100vw;
    height: 100%;
    max-height: none;
    border-radius: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .modal[open] {
    animation: fade 120ms ease-out;
  }

  @keyframes fade {
    from {
      opacity: 0;
    }
  }
}
</style>
