<script setup lang="ts">
/** The frame of every signed-in page under /posture, /investigate, /scans and /admin: the shell, and the page. */
import AppShell from '@/components/AppShell.vue'
</script>

<template>
  <AppShell>
    <RouterView />
  </AppShell>
</template>
