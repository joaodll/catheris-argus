<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { accessKeyBody, type AccessKeyInput } from '@/accessKeys'
import { ApiError, api, unwrap } from '@/api/client'
import AccessKeyFields from '@/components/AccessKeyFields.vue'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import SecretField from '@/components/SecretField.vue'
import AppModal from '@/components/AppModal.vue'
import StatusBadge from '@/components/StatusBadge.vue'

type Kind = 'demo' | 'assume_role' | 'access_key'
// demo: whether this deployment offers Demo connections (Docker Compose only).
const props = defineProps<{ demo: boolean }>()
const emit = defineEmits<{ close: []; saved: [message: string] }>()

const kind = ref<Kind>(props.demo ? 'demo' : 'assume_role')
const form = reactive({
  name: '',
  seed: 4,
  backfillDays: 180,
  accountId: '',
  roleArn: '',
  externalId: '',
})
const accessKey = ref<AccessKeyInput>({ accessKeyId: '', secret: '', sessionToken: '' })
const saving = ref(false)
const error = ref<string | null>(null)
const errorField = ref<string | null>(null)

const dirty = computed(() =>
  Boolean(form.name || form.accountId || form.roleArn || form.externalId || accessKey.value.accessKeyId || accessKey.value.secret || accessKey.value.sessionToken),
)
const submitLabel = computed(() => (kind.value === 'demo' ? 'Add and build history' : 'Add connection'))

const FIELD_HINTS: [string, string][] = [
  ['role_arn', 'roleArn'],
  ['external_id', 'externalId'],
  ['account_id', 'accountId'],
  ['access_key_id', 'accessKeyId'],
  ['secret_access_key', 'secret'],
  ['session_token', 'sessionToken'],
  ['seed', 'seed'],
  ['backfill_days', 'backfillDays'],
  ['name', 'name'],
]

function fieldError(field: string): string | null {
  return errorField.value === field ? error.value : null
}

async function submit(): Promise<void> {
  saving.value = true
  error.value = null
  errorField.value = null
  try {
    if (kind.value === 'demo') {
      await unwrap(
        api.POST('/api/v1/connections', {
          body: { kind: 'demo', name: form.name, seed: form.seed, backfill_days: form.backfillDays },
        }),
      )
      emit('saved', `${form.name} added. Building ${form.backfillDays} days of history: follow it in Runs.`)
    } else {
      await unwrap(
        api.POST('/api/v1/connections', {
          body:
            kind.value === 'assume_role'
              ? { kind: 'aws', name: form.name, account_id: form.accountId, auth_method: 'assume_role', role_arn: form.roleArn, external_id: form.externalId }
              : { kind: 'aws', name: form.name, account_id: form.accountId, auth_method: 'access_key', ...accessKeyBody(accessKey.value) },
        }),
      )
      accessKey.value = { ...accessKey.value, secret: '', sessionToken: '' }
      form.externalId = ''
      emit('saved', `${form.name} added.`)
    }
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'The connection was not added.'
    if (err instanceof ApiError && err.status === 409) error.value = 'A connection with this name or account already exists.'
    errorField.value = FIELD_HINTS.find(([api]) => error.value?.includes(api))?.[1] ?? null
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <AppModal
    wide
    title="Add connection"
    description="An account Argus collects from. Every tool reads only; nothing in the account is changed."
    :dirty="dirty"
    @close="emit('close')"
  >
    <form id="add-connection" class="form" @submit.prevent="submit">
      <AlertBanner v-if="error && !errorField" kind="fail">{{ error }}</AlertBanner>
      <fieldset class="types">
        <legend class="lbl">Type</legend>
        <label v-if="demo" class="radio-card" :class="{ 'is-selected': kind === 'demo' }">
          <input v-model="kind" type="radio" name="kind" value="demo">
          <span class="rc-text"><b>Demo</b><span class="cap">Synthetic estate. Builds history without touching a cloud.</span></span>
        </label>
        <label class="radio-card" :class="{ 'is-selected': kind === 'assume_role' }">
          <input v-model="kind" type="radio" name="kind" value="assume_role">
          <span class="rc-text">
            <span class="rc-head"><b>AWS · Assume role</b><StatusBadge status="neutral" label="Recommended" /></span>
            <span class="cap">Argus assumes a read-only role in the account with an external id.</span>
          </span>
        </label>
        <label class="radio-card" :class="{ 'is-selected': kind === 'access_key' }">
          <input v-model="kind" type="radio" name="kind" value="access_key">
          <span class="rc-text">
            <span class="rc-head"><b>AWS · Access key</b></span>
            <span class="cap">A long-lived key, or temporary SSO credentials.</span>
          </span>
        </label>
      </fieldset>

      <div class="field">
        <label class="lbl" for="c-name">Name</label>
        <input id="c-name" v-model.trim="form.name" class="input" required maxlength="100" pattern="[A-Za-z0-9 ._\-]+" :aria-invalid="fieldError('name') ? 'true' : undefined">
        <span v-if="fieldError('name')" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ fieldError('name') }}</span>
        <span class="cap">Letters, digits, spaces, dot, dash, underscore. Up to 100 characters.</span>
      </div>

      <div v-if="kind === 'demo'" class="form-grid">
        <div class="field">
          <label class="lbl" for="c-seed">Seed</label>
          <input id="c-seed" v-model.number="form.seed" class="input mono" type="number" min="0" max="89" required>
          <span class="cap">0–89. Same seed, same estate.</span>
        </div>
        <div class="field">
          <label class="lbl" for="c-days">Backfill days</label>
          <input id="c-days" v-model.number="form.backfillDays" class="input mono" type="number" min="1" max="400" required>
          <span class="cap">1–400. No cloud calls.</span>
        </div>
      </div>

      <template v-else>
        <div class="field">
          <label class="lbl" for="c-acct">Account ID</label>
          <input id="c-acct" v-model.trim="form.accountId" class="input mono" inputmode="numeric" maxlength="12" pattern="[0-9]{12}" required :aria-invalid="fieldError('accountId') ? 'true' : undefined">
          <span v-if="fieldError('accountId')" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ fieldError('accountId') }}</span>
          <span class="cap">12 digits.</span>
        </div>
        <template v-if="kind === 'assume_role'">
          <div class="field">
            <label class="lbl" for="c-arn">Role ARN</label>
            <input id="c-arn" v-model.trim="form.roleArn" class="input mono" :placeholder="`arn:aws:iam::${form.accountId || '<account id>'}:role/ArgusScanner`" required spellcheck="false" :aria-invalid="fieldError('roleArn') ? 'true' : undefined">
            <span v-if="fieldError('roleArn')" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ fieldError('roleArn') }}</span>
            <span class="cap">Must be in this account. The role grants read-only access only.</span>
          </div>
          <SecretField
            v-model="form.externalId"
            label="External ID"
            allow-generate
            :error="fieldError('externalId')"
            help="Only the scan worker can read it, and it is never shown again. Put the same value in the role's trust policy."
          />
        </template>
        <template v-else>
          <AccessKeyFields
            v-model="accessKey"
            :errors="{ accessKeyId: fieldError('accessKeyId'), secret: fieldError('secret'), sessionToken: fieldError('sessionToken') }"
          />
        </template>
      </template>
      <AlertBanner v-if="error && errorField" kind="fail">{{ error }}</AlertBanner>
    </form>
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">Cancel</button>
      <button type="submit" form="add-connection" class="btn btn-primary" :disabled="saving">
        <AppIcon v-if="saving" name="spinner" :size="16" :stroke="2.4" />{{ saving ? 'Adding…' : submitLabel }}
      </button>
    </template>
  </AppModal>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
}

.types {
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
