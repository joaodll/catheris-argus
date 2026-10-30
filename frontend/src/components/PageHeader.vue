<script setup lang="ts">
/** CatherIs Platform's page header (design-system.md, Page header): the page's h1, which
 * receives focus after each navigation (see router.ts), the subtitle under it (the default
 * slot: the page's scope), and the page's actions on the right (the actions slot). */
defineProps<{ title: string }>()
</script>

<template>
  <header class="page-header">
    <div class="titles">
      <h1 tabindex="-1" data-page-title>{{ title }}</h1>
      <p v-if="$slots.default" class="page-subtitle"><slot /></p>
    </div>
    <div v-if="$slots.actions" class="actions"><slot name="actions" /></div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--s-12);
  margin-bottom: var(--s-8);
}

.titles {
  min-width: 0;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-12);
}
</style>
