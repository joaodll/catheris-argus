<script setup lang="ts">
/**
 * CatherIs Platform's sign-in page and card (docs/ui/screens.md, E1), shared by Sign in and
 * Choose a new password: aurora, grid and a slow scan sweep behind a glass card; all still
 * under reduced motion. The card's content goes in the default slot, the caption under it in
 * `below`.
 */
import AppIcon from './AppIcon.vue'
</script>

<template>
  <div class="page">
    <div class="aurora" aria-hidden="true"></div>
    <div class="grid-bg" aria-hidden="true"></div>
    <div class="scan" aria-hidden="true"></div>

    <div class="column">
      <main class="auth">
        <div class="top">
          <div class="logo">
            <span class="mark"><AppIcon name="shield" :size="24" :stroke="1.8" /></span>
            <span class="word"><b>CatherIs</b><span>Argus</span></span>
          </div>
          <span class="sysdot"><i aria-hidden="true"></i>READ-ONLY</span>
        </div>
        <slot />
        <div class="foot">
          <span>Prowler · CloudFox · Steampipe</span>
          <span class="pill">Audited</span>
        </div>
      </main>
      <slot name="below" />
    </div>
  </div>
</template>

<style scoped>
.page {
  position: relative;
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: var(--s-32) var(--s-16);
  overflow: hidden;
  background: radial-gradient(ellipse at 50% 8%, var(--surface-raised) 0%, var(--bg) 60%);
}

.page .aurora {
  position: absolute;
}

/* The scan sweep: the page's one moment of motion. */
.scan {
  position: absolute;
  inset: 0 0 auto;
  height: 2px;
  z-index: 1;
  pointer-events: none;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  box-shadow: 0 0 22px 3px var(--accent-wash);
  opacity: 0.5;
  animation: sweep 7s cubic-bezier(0.5, 0, 0.5, 1) infinite;
}

@keyframes sweep {
  0% {
    transform: translateY(6vh);
    opacity: 0;
  }

  12%,
  88% {
    opacity: 0.6;
  }

  100% {
    transform: translateY(94vh);
    opacity: 0;
  }
}

.column {
  position: relative;
  z-index: 2;
  width: 100%;
  max-width: 394px;
  display: flex;
  flex-direction: column;
  gap: var(--s-20);
}

.auth {
  position: relative;
  padding: 38px 36px 34px;
  background: var(--glass-fill);
  backdrop-filter: var(--glass-blur);
  border: 1px solid var(--border-strong);
  border-radius: 20px;
  box-shadow: var(--shadow-sheet), inset 0 1px 0 rgb(92 225 230 / 16%);
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
}

/* The lit edge all around the border. */
.auth::before {
  content: '';
  position: absolute;
  inset: 0;
  padding: 1px;
  border-radius: inherit;
  background: var(--lit-edge);
  mask:
    linear-gradient(#000, #000) content-box,
    linear-gradient(#000, #000);
  mask-composite: exclude;
  pointer-events: none;
}

.top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-12);
  margin-bottom: var(--s-10);
}

.logo {
  display: flex;
  align-items: center;
  gap: 11px;
}

.mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 46px;
  height: 46px;
  border-radius: 13px;
  background: linear-gradient(145deg, var(--accent), var(--accent-active));
  color: var(--on-accent);
  box-shadow: var(--glow-accent), inset 0 1px 0 rgb(255 255 255 / 14%);
}

.word {
  display: flex;
  flex-direction: column;
  line-height: 1.3;
}

.word b {
  font-size: 17px;
  letter-spacing: -0.01em;
}

.word span {
  font-size: 10.5px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-3);
}

.sysdot {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
  padding: 4px 9px;
  border: 1px solid var(--border);
  border-radius: var(--r-pill);
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-3);
}

.sysdot i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--status-ok);
  box-shadow: 0 0 8px var(--status-ok);
  animation: blink 2.4s ease infinite;
}

@keyframes blink {
  50% {
    opacity: 0.35;
  }
}

/* The content both pages put in the card. */
:slotted(h1) {
  font-size: 19px;
  letter-spacing: -0.02em;
}

:slotted(.sub) {
  margin: -12px 0 var(--s-8);
  font-size: 12.5px;
  color: var(--text-3);
}

:slotted(.form) {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

:slotted(.center) {
  margin: 0;
  text-align: center;
}

.foot {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--s-8);
  margin-top: 6px;
  padding-top: var(--s-16);
  border-top: 1px solid var(--border);
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--text-3);
}

.pill {
  padding: 2px 9px;
  border: 1px solid color-mix(in srgb, var(--accent) 30%, transparent);
  border-radius: var(--r-pill);
  color: var(--link);
}

@media (max-width: 600px) {
  .auth {
    padding: 28px 22px 24px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .scan {
    animation: none;
    opacity: 0.4;
  }
}
</style>
