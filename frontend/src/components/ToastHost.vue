<script setup lang="ts">
/** CatherIs Platform's toasts (design-system.md, Toast): typed, dismissible, paused on hover. */
import { dismiss, pause, resume, toasts, type ToastKind } from '@/composables/useToasts'
import AppIcon from './AppIcon.vue'

const GLYPH: Record<ToastKind, string> = { success: '✓', info: 'i', warning: '!', error: '✕' }
</script>

<template>
  <Teleport to="body">
    <div class="toasts">
      <!-- Errors are announced at once; the rest politely. -->
      <div class="region" role="status" aria-live="polite">
        <template v-for="t in toasts" :key="t.id">
          <div
            v-if="t.kind !== 'error'"
            class="toast"
            :class="t.kind"
            @mouseenter="pause(t.id)"
            @mouseleave="resume(t.id)"
            @focusin="pause(t.id)"
            @focusout="resume(t.id)"
          >
            <span class="glyph" aria-hidden="true">{{ GLYPH[t.kind] }}</span>
            <span class="text">{{ t.text }}</span>
            <button type="button" class="close" aria-label="Dismiss" @click="dismiss(t.id)"><AppIcon name="cross" :size="12" :stroke="2.4" /></button>
          </div>
        </template>
      </div>
      <div class="region" role="alert" aria-live="assertive">
        <template v-for="t in toasts" :key="t.id">
          <div
            v-if="t.kind === 'error'"
            class="toast error"
            @mouseenter="pause(t.id)"
            @mouseleave="resume(t.id)"
            @focusin="pause(t.id)"
            @focusout="resume(t.id)"
          >
            <span class="glyph" aria-hidden="true">{{ GLYPH.error }}</span>
            <span class="text">{{ t.text }}</span>
            <button type="button" class="close" aria-label="Dismiss" @click="dismiss(t.id)"><AppIcon name="cross" :size="12" :stroke="2.4" /></button>
          </div>
        </template>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.toasts {
  position: fixed;
  right: 20px;
  bottom: 20px;
  z-index: 1100;
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  width: min(420px, calc(100vw - 32px));
}

.region {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.region:empty {
  display: none;
}

.toast {
  --tone: var(--status-ok);

  display: flex;
  gap: var(--s-10);
  align-items: flex-start;
  padding: var(--s-12) var(--s-14);
  background: color-mix(in srgb, var(--tone) 12%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--tone) 30%, transparent);
  border-radius: var(--r-tile);
  box-shadow: var(--shadow-sheet);
  color: var(--text);
  font-size: 13px;
  line-height: 1.5;
  animation: slide-in 200ms ease-out;
}

.toast.info {
  --tone: var(--status-run);
}

.toast.warning {
  --tone: var(--status-warn);
}

.toast.error {
  --tone: var(--status-fail);
}

.glyph {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  border-radius: 50%;
  background: color-mix(in srgb, var(--tone) 22%, transparent);
  color: var(--tone);
  font-size: 11px;
  font-weight: 700;
}

.toast.error .glyph {
  color: var(--sev-critical-text);
}

.text {
  flex: 1;
  min-width: 0;
  padding-top: 1px;
}

.close {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  flex-shrink: 0;
  margin: -2px -4px 0 0;
  padding: 0;
  border: 0;
  border-radius: var(--r-control);
  background: none;
  color: var(--text-2);
  cursor: pointer;
}

.close:hover {
  background: var(--surface-raised);
  color: var(--text);
}

@keyframes slide-in {
  from {
    opacity: 0;
    transform: translateX(24px);
  }
}

@media (max-width: 600px) {
  .toasts {
    left: var(--s-16);
    right: var(--s-16);
    bottom: var(--s-16);
    width: auto;
  }
}

@media (prefers-reduced-motion: reduce) {
  .toast {
    animation: fade 150ms ease-out;
  }

  @keyframes fade {
    from {
      opacity: 0;
    }
  }
}
</style>
