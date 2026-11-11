<script setup lang="ts" generic="T extends string">
/**
 * The two ways an AWS connection signs in, as radio cards (palace spec frontend/7dcc40d5): Add
 * connection and Edit connection share them, so their words never drift. The parent holds the
 * fieldset and its legend; Add puts its Demo card beside these.
 */
import StatusBadge from '@/components/StatusBadge.vue'

defineProps<{ name: string }>()
// T: the parent's own choice type (Add's includes 'demo'); these cards set only the AWS two.
const method = defineModel<T>({ required: true })
</script>

<template>
  <label class="radio-card" :class="{ 'is-selected': method === 'assume_role' }">
    <input v-model="method" type="radio" :name="name" value="assume_role">
    <span class="rc-text">
      <span class="rc-head"><b>AWS · Assume role</b><StatusBadge status="neutral" label="Recommended" /></span>
      <span class="cap">Argus assumes a read-only role in the account with an external id.</span>
    </span>
  </label>
  <label class="radio-card" :class="{ 'is-selected': method === 'access_key' }">
    <input v-model="method" type="radio" :name="name" value="access_key">
    <span class="rc-text">
      <span class="rc-head"><b>AWS · Access key</b></span>
      <span class="cap">A long-lived key, or temporary SSO credentials.</span>
    </span>
  </label>
</template>

<style scoped>
.rc-text {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.rc-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--s-8);
}

.rc-text b {
  font-size: 14px;
  font-weight: 600;
}
</style>
