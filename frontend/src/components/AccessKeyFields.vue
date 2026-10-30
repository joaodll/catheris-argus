<script setup lang="ts">
/**
 * An AWS access key, entered whole: the key id, its secret and, for a temporary key (ASIA...),
 * its session token. The token field appears only when the key id says it is needed.
 */
import { computed, useId } from 'vue'
import { isTemporaryKey, type AccessKeyInput } from '@/accessKeys'
import AppIcon from './AppIcon.vue'
import SecretField from './SecretField.vue'

const props = defineProps<{
  modelValue: AccessKeyInput
  errors?: { accessKeyId?: string | null; secret?: string | null; sessionToken?: string | null }
}>()
const emit = defineEmits<{ 'update:modelValue': [value: AccessKeyInput] }>()

const id = useId()
const temporary = computed(() => isTemporaryKey(props.modelValue.accessKeyId))

function set(field: keyof AccessKeyInput, value: string): void {
  emit('update:modelValue', { ...props.modelValue, [field]: value })
}
</script>

<template>
  <div class="field">
    <label class="lbl" :for="id">Access key ID</label>
    <input
      :id="id"
      class="input mono"
      autocomplete="off"
      spellcheck="false"
      required
      :value="props.modelValue.accessKeyId"
      :aria-invalid="props.errors?.accessKeyId ? 'true' : undefined"
      :aria-describedby="`${id}-help`"
      @input="set('accessKeyId', ($event.target as HTMLInputElement).value.trim())"
    >
    <span v-if="props.errors?.accessKeyId" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ props.errors.accessKeyId }}</span>
    <span :id="`${id}-help`" class="cap">AKIA… is a long-lived key. ASIA… is a temporary (SSO) key and needs its session token.</span>
  </div>
  <SecretField
    :model-value="props.modelValue.secret"
    label="Secret access key"
    :error="props.errors?.secret"
    @update:model-value="set('secret', $event)"
  />
  <SecretField
    v-if="temporary"
    class="wide"
    :model-value="props.modelValue.sessionToken"
    label="Session token"
    :error="props.errors?.sessionToken"
    help="Temporary keys expire. When runs fail with an expired token, paste a fresh set here. Stored encrypted, never shown again."
    @update:model-value="set('sessionToken', $event)"
  />
</template>

<style scoped>
/* A session token is long: in a two-column form grid it takes the whole row. */
.wide {
  grid-column: 1 / -1;
}
</style>
