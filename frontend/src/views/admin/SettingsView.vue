<script setup lang="ts">
import { provide } from 'vue'
import { api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import PageHeader from '@/components/PageHeader.vue'
import { useResource } from '@/composables/useResource'
import CollectionForm from './CollectionForm.vue'
import IdentityForm from './IdentityForm.vue'
import RawStorageForm from './RawStorageForm.vue'
import RetentionForm from './RetentionForm.vue'
import { SETTINGS_SECTIONS, settingsSections } from './settingsSections'

const settings = useResource(() => unwrap(api.GET('/api/v1/settings')))

// The "On this page" list: every card registers itself (SettingsCard).
const sections = settingsSections()
provide(SETTINGS_SECTIONS, sections)

function goTo(id: string): void {
  const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
  document.getElementById(`${id}-h`)?.closest('section')?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' })
}
</script>

<template>
  <PageHeader title="Settings">Every change here is recorded in the audit log.</PageHeader>
  <div class="layout">
    <nav v-if="sections.list.length" class="toc" aria-label="On this page">
      <span class="eyebrow">On this page</span>
      <ul>
        <li v-for="s in sections.list" :key="s.id">
          <a :href="`#${s.id}-h`" @click.prevent="goTo(s.id)">
            {{ s.title }}<span v-if="s.dirty" class="dot-warn" aria-hidden="true"></span><span v-if="s.dirty" class="sr-only"> (unsaved)</span>
          </a>
        </li>
      </ul>
    </nav>
    <div class="cards">
      <AlertBanner v-if="settings.error.value" kind="fail">
        Settings didn't load: {{ settings.error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="settings.reload">Retry</button></template>
      </AlertBanner>
      <template v-else-if="settings.data.value">
        <CollectionForm :settings="settings.data.value" @saved="(s) => (settings.data.value = s)" />
        <RetentionForm :settings="settings.data.value" @saved="(s) => (settings.data.value = s)" />
        <RawStorageForm :settings="settings.data.value" @saved="(s) => (settings.data.value = s)" />
        <IdentityForm :settings="settings.data.value" @saved="(s) => (settings.data.value = s)" />
      </template>
      <div v-else aria-busy="true" class="cards">
        <div v-for="n in 4" :key="n" class="card skeleton sk-220"></div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* From 1150 px: the section list on the left, the cards on the right (at most 920 px). */
.layout {
  display: grid;
  grid-template-columns: 220px minmax(0, 920px);
  gap: var(--s-24);
  align-items: start;
}

.toc {
  position: sticky;
  top: var(--s-16);
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
  padding-top: var(--s-6);
}

.toc .eyebrow {
  color: var(--text-3);
}

.toc ul {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: var(--s-2);
}

.toc a {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-8);
  padding: 6px var(--s-10);
  border-radius: var(--r-control);
  color: var(--text-2);
  font-size: 13px;
  text-decoration: none;
}

.toc a:hover {
  background: var(--surface-raised);
  color: var(--text);
}

.toc a:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}

.dot-warn {
  flex: none;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--status-warn);
}

.cards {
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
  min-width: 0;
}

@media (max-width: 1149px) {
  .layout {
    grid-template-columns: minmax(0, 1fr);
  }

  .toc {
    display: none;
  }
}
</style>
