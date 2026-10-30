<script setup lang="ts">
import { computed, ref } from 'vue'
import { accessKeyBody, type AccessKeyInput } from '@/accessKeys'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AccessKeyFields from '@/components/AccessKeyFields.vue'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import MaskedValue from '@/components/MaskedValue.vue'
import SwitchToggle from '@/components/SwitchToggle.vue'
import TestConnection from './TestConnection.vue'

// `readonly`: a Viewer sees the connection, and nothing it could change (ADR-0041).
const props = defineProps<{ connection: Schemas['ConnectionOut']; readonly?: boolean }>()
const emit = defineEmits<{ close: []; saved: [message: string] }>()

const name = ref(props.connection.name)
const enabled = ref(props.connection.enabled)
// A replacement is the whole key: a rotated key or a new SSO session changes every part.
const replacing = ref(false)
const key = ref<AccessKeyInput>({ accessKeyId: '', secret: '', sessionToken: '' })
const saving = ref(false)
const error = ref<string | null>(null)

const dirty = computed(() => name.value !== props.connection.name || enabled.value !== props.connection.enabled || replacing.value)
const auth = computed(() =>
  props.connection.kind === 'demo' ? 'Synthetic' : props.connection.auth_method === 'assume_role' ? 'Assume role' : 'Access key',
)

async function save(): Promise<void> {
  saving.value = true
  error.value = null
  const body: Schemas['ConnectionPatch'] = {}
  if (name.value !== props.connection.name) body.name = name.value
  if (enabled.value !== props.connection.enabled) body.enabled = enabled.value
  if (replacing.value) body.access_key = accessKeyBody(key.value)
  try {
    await unwrap(api.PATCH('/api/v1/connections/{connection_id}', { params: { path: { connection_id: props.connection.id } }, body }))
    stopReplacing()
    emit('saved', `${name.value} saved.`)
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The changes were not saved.'
  } finally {
    saving.value = false
  }
}

function stopReplacing(): void {
  replacing.value = false
  key.value = { accessKeyId: '', secret: '', sessionToken: '' }
}
</script>

<template>
  <AppModal
    wide
    :title="props.connection.name"
    :description="`${props.connection.kind === 'demo' ? 'Demo' : 'AWS'} · ${auth} · updated by ${props.connection.updated_by} on ${props.connection.updated_at.slice(0, 10)}`"
    :dirty="dirty"
    @close="emit('close')"
  >
    <form id="edit-connection" class="form" @submit.prevent="save">
      <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
      <span v-if="props.readonly" class="cap">Only an operator or admin can change connections.</span>
      <fieldset class="plain" :disabled="props.readonly">
        <div class="field">
          <label class="lbl" for="e-name">Name</label>
          <input id="e-name" v-model.trim="name" class="input" required maxlength="100">
        </div>
        <div class="field">
          <span class="lbl">Collection</span>
          <SwitchToggle v-model="enabled" :label="`Collection for ${props.connection.name}`" />
          <span class="cap">Disable to stop collection. History is kept.</span>
        </div>
        <div v-if="props.connection.auth_method === 'access_key'" class="field">
          <span class="lbl">Access key</span>
          <div v-if="!replacing" class="set-line">
            <span>
              <span class="mono">{{ props.connection.access_key_id_hint }}</span> · secret <MaskedValue />
              <template v-if="props.connection.secret_set_at"> · set on <span class="mono">{{ props.connection.secret_set_at.slice(0, 10) }}</span></template>
            </span>
            <button v-if="!props.readonly" type="button" class="btn btn-secondary btn-sm" @click="replacing = true">Replace</button>
          </div>
          <span v-else class="cap">Enter the whole new key. The current one stays in use until you save.</span>
        </div>
        <template v-if="replacing">
          <AccessKeyFields v-model="key" />
          <button type="button" class="btn btn-secondary btn-sm cancel" @click="stopReplacing">Cancel replacing</button>
        </template>
      </fieldset>
      <dl class="facts">
        <dt class="lbl">Account</dt><dd class="mono">{{ props.connection.account_id }}</dd>
        <template v-if="props.connection.role_arn"><dt class="lbl">Role</dt><dd class="mono arn">{{ props.connection.role_arn }}</dd></template>
        <template v-if="props.connection.auth_method === 'assume_role'">
          <dt class="lbl">External ID</dt>
          <dd><MaskedValue v-if="props.connection.external_id_set" /><template v-else>None</template></dd>
        </template>
        <template v-if="props.connection.access_key_id_hint"><dt class="lbl">Access key ID</dt><dd class="mono">{{ props.connection.access_key_id_hint }}</dd></template>
        <dt class="lbl">Authentication</dt><dd>{{ auth }}</dd>
      </dl>
      <span v-if="props.connection.kind !== 'demo'" class="cap">To change the account or how it signs in, add a new connection and disable this one.</span>
      <TestConnection v-if="props.connection.kind === 'aws' && !props.readonly" target="connection" :connection-id="props.connection.id" :dirty="dirty" />
    </form>
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">{{ props.readonly ? 'Close' : 'Cancel' }}</button>
      <button v-if="!props.readonly" type="submit" form="edit-connection" class="btn btn-primary" :disabled="saving || !dirty">
        <AppIcon v-if="saving" name="spinner" :size="16" :stroke="2.4" />{{ saving ? 'Saving…' : 'Save changes' }}
      </button>
    </template>
  </AppModal>
</template>

<style scoped>
.form,
.plain {
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
}

/* Groups the editable fields, so a Viewer's copy disables them all at once. */
.plain {
  margin: 0;
  padding: 0;
  border: 0;
  min-width: 0;
}

.facts {
  margin: 0;
  padding-top: var(--s-14);
  border-top: 1px solid var(--border);
  display: grid;
  grid-template-columns: 140px minmax(0, 1fr);
  gap: var(--s-8) var(--s-12);
  font-size: 13px;
}

.facts dt {
  padding-top: 2px;
}

.facts dd {
  margin: 0;
}

.arn {
  word-break: break-all;
}

.set-line {
  display: flex;
  align-items: center;
  gap: var(--s-10);
  flex-wrap: wrap;
  font-size: 13px;
}

.cancel {
  align-self: flex-start;
}
</style>
