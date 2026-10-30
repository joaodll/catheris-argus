<script setup lang="ts">
/**
 * A stored secret or ExternalId (design-system.md, Masked value): eight asterisks whatever the
 * value, so neither a character nor its length shows. A screen reader hears "hidden".
 */
</script>

<template>
  <span class="mono"><span aria-hidden="true">********</span><span class="sr-only">hidden</span></span>
</template>
