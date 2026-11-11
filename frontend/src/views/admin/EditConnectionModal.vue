<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { accessKeyBody, type AccessKeyInput } from '@/accessKeys'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AccessKeyFields from '@/components/AccessKeyFields.vue'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import MaskedValue from '@/components/MaskedValue.vue'
import SecretField from '@/components/SecretField.vue'
import SwitchToggle from '@/components/SwitchToggle.vue'
import SignInMethodCards from './SignInMethodCards.vue'
import TestConnection from './TestConnection.vue'

// `readonly`: a Viewer sees the connection, and nothing it could change (ADR-0041).
const props = defineProps<{ connection: Schemas['ConnectionOut']; readonly?: boolean }>()
const emit = defineEmits<{ close: []; saved: [message: string] }>()

const name = ref(props.connection.name)
const enabled = ref(props.connection.enabled)
// A replacement is the whole key: a rotated key or a new SSO session changes every part.
const replacing = ref(false)
const key = ref<AccessKeyInput>({ accessKeyId: '', secret: '', sessionToken: '' })
// An assume-role connection's role can change within its account (owner, 2026-11-06). The
// ExternalId is write-only: kept, set (or replaced), or removed; never shown.
const roleArn = ref(props.connection.role_arn ?? '')
const externalId = ref<'keep' | 'set' | 'clear'>('keep')
const newExternalId = ref('')
// The sign-in method can switch (owner, 2026-11-09; spec frontend/7dcc40d5): the other method's
// whole set is entered here, and saving deletes the stored method's credentials.
type Method = 'assume_role' | 'access_key'
const method = ref<Method>(props.connection.auth_method === 'access_key' ? 'access_key' : 'assume_role')
const switching = computed(() => props.connection.kind === 'aws' && method.value !== props.connection.auth_method)
const switchRoleArn = ref('')
const switchExternalId = ref('')
const switchKey = ref<AccessKeyInput>({ accessKeyId: '', secret: '', sessionToken: '' })
// Back on the stored method: what was typed for the other one is discarded.
watch(switching, (now) => {
  if (!now) {
    switchRoleArn.value = ''
    switchExternalId.value = ''
    switchKey.value = { accessKeyId: '', secret: '', sessionToken: '' }
  }
})
const switchNote = computed(() => {
  const toRole = method.value === 'assume_role'
  const stored = toRole
    ? 'access key and its secret are'
    : `role${props.connection.external_id_set ? ' and its external ID are' : ' is'}`
  return (
    `Saving switches ${props.connection.name} to ${toRole ? 'Assume role' : 'an access key'}. ` +
    `The stored ${stored} deleted and can't be shown or recovered. A run already collecting ` +
    'finishes with them; the next run uses the new method. Run Test connection after saving.' +
    (toRole ? ' Then deactivate the old key in IAM.' : '')
  )
})
const saving = ref(false)
const error = ref<string | null>(null)

const assumeRole = computed(() => props.connection.auth_method === 'assume_role')
const roleChanged = computed(() => assumeRole.value && roleArn.value !== (props.connection.role_arn ?? ''))
const externalIdChanged = computed(() => externalId.value === 'clear' || (externalId.value === 'set' && newExternalId.value !== ''))
const dirty = computed(
  () =>
    name.value !== props.connection.name ||
    enabled.value !== props.connection.enabled ||
    switching.value ||
    replacing.value ||
    roleChanged.value ||
    externalIdChanged.value,
)
const auth = computed(() =>
  props.connection.kind === 'demo' ? 'Synthetic' : props.connection.auth_method === 'assume_role' ? 'Assume role' : 'Access key',
)

async function save(): Promise<void> {
  saving.value = true
  error.value = null
  const body: Schemas['ConnectionPatch'] = {}
  if (name.value !== props.connection.name) body.name = name.value
  if (enabled.value !== props.connection.enabled) body.enabled = enabled.value
  if (switching.value) {
    // The new method's whole set, and nothing for the stored one.
    body.auth_method = method.value
    if (method.value === 'access_key') body.access_key = accessKeyBody(switchKey.value)
    else body.assume_role = { role_arn: switchRoleArn.value, ...(switchExternalId.value ? { external_id: switchExternalId.value } : {}), clear_external_id: false }
  } else if (replacing.value) body.access_key = accessKeyBody(key.value)
  if (!switching.value && (roleChanged.value || externalIdChanged.value)) {
    body.assume_role = {
      ...(roleChanged.value ? { role_arn: roleArn.value } : {}),
      ...(externalId.value === 'set' && newExternalId.value ? { external_id: newExternalId.value } : {}),
      clear_external_id: externalId.value === 'clear',
    }
  }
  try {
    await unwrap(api.PATCH('/api/v1/connections/{connection_id}', { params: { path: { connection_id: props.connection.id } }, body }))
    stopReplacing()
    keepExternalId()
    emit('saved', `${name.value} saved.`)
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The changes were not saved.'
  } finally {
    saving.value = false
  }
}

function keepExternalId(): void {
  externalId.value = 'keep'
  newExternalId.value = ''
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
        <fieldset v-if="props.connection.kind === 'aws'" class="types">
          <legend class="lbl">Sign-in method</legend>
          <SignInMethodCards v-model="method" name="e-method" />
        </fieldset>
        <template v-if="switching">
          <template v-if="method === 'assume_role'">
            <div class="field">
              <label class="lbl" for="e-new-arn">Role ARN</label>
              <input id="e-new-arn" v-model.trim="switchRoleArn" class="input mono" :placeholder="`arn:aws:iam::${props.connection.account_id}:role/ArgusScanner`" required spellcheck="false">
              <span class="cap">Must be in account <span class="mono">{{ props.connection.account_id }}</span>. The role grants read-only access only.</span>
            </div>
            <SecretField
              v-model="switchExternalId"
              label="External ID (optional)"
              allow-generate
              help="Only if the role's trust policy asks for one: then put the same value there, 16 or more characters. Only the scan worker can read it, and it is never shown again."
            />
          </template>
          <AccessKeyFields v-else v-model="switchKey" />
          <AlertBanner kind="warn">{{ switchNote }}</AlertBanner>
        </template>
        <div v-if="!switching && props.connection.auth_method === 'access_key'" class="field">
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
        <template v-if="!switching && replacing">
          <AccessKeyFields v-model="key" />
          <button type="button" class="btn btn-secondary btn-sm cancel" @click="stopReplacing">Cancel replacing</button>
        </template>
        <template v-if="!switching && assumeRole">
          <div class="field">
            <label class="lbl" for="e-arn">Role ARN</label>
            <input id="e-arn" v-model.trim="roleArn" class="input mono" required spellcheck="false">
            <span class="cap">Must be in account <span class="mono">{{ props.connection.account_id }}</span>. The current role stays in use until you save.</span>
          </div>
          <div v-if="externalId !== 'set'" class="field">
            <span class="lbl">External ID</span>
            <div class="set-line">
              <span v-if="externalId === 'clear'">Removed when you save</span>
              <MaskedValue v-else-if="props.connection.external_id_set" />
              <span v-else>None</span>
              <template v-if="!props.readonly">
                <button v-if="externalId === 'clear'" type="button" class="btn btn-secondary btn-sm" @click="keepExternalId">Keep it</button>
                <template v-else>
                  <button type="button" class="btn btn-secondary btn-sm" @click="externalId = 'set'">{{ props.connection.external_id_set ? 'Replace' : 'Set' }}</button>
                  <button v-if="props.connection.external_id_set" type="button" class="btn btn-secondary btn-sm" @click="externalId = 'clear'">Remove</button>
                </template>
              </template>
            </div>
          </div>
          <template v-else>
            <SecretField
              v-model="newExternalId"
              label="New external ID"
              allow-generate
              help="Put the same value in the role's trust policy, 16 or more characters. Only the scan worker can read it, and it is never shown again."
            />
            <button type="button" class="btn btn-secondary btn-sm cancel" @click="keepExternalId">{{ props.connection.external_id_set ? 'Keep the current one' : 'Cancel' }}</button>
          </template>
        </template>
      </fieldset>
      <dl class="facts">
        <dt class="lbl">Account</dt><dd class="mono">{{ props.connection.account_id }}</dd>
        <template v-if="props.connection.access_key_id_hint"><dt class="lbl">Access key ID</dt><dd class="mono">{{ props.connection.access_key_id_hint }}</dd></template>
        <dt class="lbl">Authentication</dt><dd>{{ auth }}</dd>
      </dl>
      <span v-if="props.connection.kind !== 'demo'" class="cap">To change the account, add a new connection and disable this one: the account is what its history belongs to.</span>
      <TestConnection v-if="props.connection.kind === 'aws' && !props.readonly" target="connection" :connection-id="props.connection.id" :dirty="dirty" />
    </form>
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">{{ props.readonly ? 'Close' : 'Cancel' }}</button>
      <button v-if="!props.readonly" type="submit" form="edit-connection" class="btn btn-primary" :disabled="saving || !dirty">
        <AppIcon v-if="saving" name="spinner" :size="16" :stroke="2.4" />{{ saving ? 'Saving…' : switching ? 'Switch and save' : 'Save changes' }}
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

.types {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  margin: 0;
  padding: 0;
  border: 0;
  min-width: 0;
}
</style>
