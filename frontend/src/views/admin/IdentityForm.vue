<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { accessKeyBody, type AccessKeyInput } from '@/accessKeys'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AccessKeyFields from '@/components/AccessKeyFields.vue'
import MaskedValue from '@/components/MaskedValue.vue'
import { useDirtyGuard } from '@/composables/useDirtyGuard'
import { toast } from '@/composables/useToasts'
import SettingsCard from './SettingsCard.vue'
import TestConnection from './TestConnection.vue'

type Mode = 'ambient' | 'access_key'
const props = defineProps<{ settings: Schemas['SettingsOut'] }>()
const emit = defineEmits<{ saved: [settings: Schemas['SettingsOut']] }>()

const mode = ref<Mode>(props.settings.identity.mode as Mode)
const key = ref<AccessKeyInput>(stored())
// Only when this topic's values change: another card's save must not discard edits here.
watch(() => JSON.stringify(props.settings.identity), () => discard())
const dirty = computed(
  () =>
    mode.value !== props.settings.identity.mode ||
    key.value.accessKeyId !== (props.settings.identity.access_key_id ?? '') ||
    key.value.secret !== '' ||
    key.value.sessionToken !== '',
)
useDirtyGuard(dirty)

const saving = ref(false)
const error = ref<string | null>(null)

// The secret and the session token are never read back: the form starts with the key id only.
function stored(): AccessKeyInput {
  return { accessKeyId: props.settings.identity.access_key_id ?? '', secret: '', sessionToken: '' }
}

function discard(): void {
  mode.value = props.settings.identity.mode as Mode
  key.value = stored()
}

async function save(): Promise<void> {
  saving.value = true
  error.value = null
  try {
    const result = await unwrap(
      api.PUT('/api/v1/settings/identity', {
        body: mode.value === 'ambient' ? { mode: 'ambient' } : { mode: 'access_key', ...accessKeyBody(key.value) },
      }),
    )
    key.value = { ...key.value, secret: '', sessionToken: '' }
    emit('saved', result)
    toast('Platform identity saved. The change is in the audit log.')
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The identity was not saved.'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <SettingsCard
    id="identity"
    title="Platform identity"
    description="How Argus signs in to AWS before it assumes each connection's role."
    :dirty="dirty"
    :saving="saving"
    :error="error"
    save-label="Save identity"
    @save="save"
    @discard="discard"
  >
    <fieldset class="modes">
      <legend class="lbl">Identity</legend>
      <label class="radio-card" :class="{ 'is-selected': mode === 'ambient' }">
        <input v-model="mode" type="radio" name="identity" value="ambient">
        <span class="rc-text"><b>Ambient</b><span class="cap">The instance or pod role.</span></span>
      </label>
      <label class="radio-card" :class="{ 'is-selected': mode === 'access_key' }">
        <input v-model="mode" type="radio" name="identity" value="access_key">
        <span class="rc-text"><b>Access key</b><span class="cap">A long-lived key, or temporary SSO credentials.</span></span>
      </label>
    </fieldset>
    <div v-if="mode === 'access_key'" class="form-grid">
      <AccessKeyFields v-model="key" />
    </div>
    <span v-if="mode === 'access_key' && props.settings.identity.secret_set && props.settings.identity.mode === 'access_key'" class="cap">
      A key is stored (secret <MaskedValue />). Saving replaces it: enter its secret, and for a temporary key its session token, again.
    </span>
    <span class="cap">This identity needs sts:AssumeRole and write access to the raw output bucket. Every scan runs as the connection's read-only role.</span>
    <TestConnection target="identity" :dirty="dirty" />
  </SettingsCard>
</template>

<style scoped>
.modes {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.rc-text {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}


.rc-text b {
  font-size: 14px;
  font-weight: 600;
}
</style>
