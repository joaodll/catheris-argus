<script setup lang="ts">
/**
 * Edit user (docs/ui/screens.md, E13): display name, email, role and active flag (PATCH /users/{id}),
 * and three actions with their own result: set a new password, unlock, delete (inactive only).
 * Your own role and active flag, and the last active admin's, are locked here; the API refuses
 * them anyway (409).
 */
import { computed, ref } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import SecretField from '@/components/SecretField.vue'
import SwitchToggle from '@/components/SwitchToggle.vue'
import { session } from '@/composables/useSession'
import { newPasswordProblem } from '@/passwords'
import RoleCards from './RoleCards.vue'

const props = defineProps<{ user: Schemas['UserOut']; activeAdmins: number }>()
const emit = defineEmits<{ close: []; saved: [message: string] }>()

const displayName = ref(props.user.display_name)
const email = ref(props.user.email ?? '')
const role = ref(props.user.role)
const active = ref(props.user.is_active)
const saving = ref(false)
const error = ref<string | null>(null)

const settingPassword = ref(false)
const password = ref('')
const passwordError = ref<string | null>(null)
const acting = ref<'password' | 'unlock' | 'delete' | null>(null)

const isMe = computed(() => props.user.username === session.value?.username)
// An SSO user's role, email and sign-in come from the identity provider (ADR-0048).
const sso = computed(() => props.user.auth_source === 'saml')
const lastAdmin = computed(
  () => !sso.value && props.user.role === 'admin' && props.user.is_active && props.activeAdmins <= 1,
)
const locked = computed(() => isMe.value || lastAdmin.value)
const lockReason = computed(() =>
  isMe.value
    ? "You can't change your own role or deactivate yourself."
    : 'Argus needs at least one active admin who signs in with a password.',
)
const dirty = computed(
  () =>
    displayName.value !== props.user.display_name ||
    email.value !== (props.user.email ?? '') ||
    role.value !== props.user.role ||
    active.value !== props.user.is_active,
)
const who = computed(() => props.user.display_name || props.user.username)

function failure(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback
}

async function save(): Promise<void> {
  saving.value = true
  error.value = null
  const body: Schemas['UserPatch'] = {}
  if (displayName.value !== props.user.display_name) body.display_name = displayName.value
  if (email.value !== (props.user.email ?? '')) body.email = email.value
  if (role.value !== props.user.role) body.role = role.value
  if (active.value !== props.user.is_active) body.is_active = active.value
  try {
    await unwrap(api.PATCH('/api/v1/users/{user_id}', { params: { path: { user_id: props.user.id } }, body }))
    emit('saved', `${props.user.username} saved.`)
  } catch (err) {
    error.value = failure(err, 'The changes were not saved.')
  } finally {
    saving.value = false
  }
}

async function setPassword(): Promise<void> {
  passwordError.value = newPasswordProblem(password.value, password.value, props.user.username)?.message ?? null
  if (passwordError.value) return
  acting.value = 'password'
  error.value = null
  try {
    await unwrap(
      api.POST('/api/v1/users/{user_id}/password', { params: { path: { user_id: props.user.id } }, body: { password: password.value } }),
    )
    emit('saved', `New password set for ${props.user.username}. They choose their own at the next sign-in.`)
  } catch (err) {
    error.value = failure(err, 'The password was not set.')
  } finally {
    acting.value = null
  }
}

async function unlock(): Promise<void> {
  acting.value = 'unlock'
  error.value = null
  try {
    await unwrap(api.POST('/api/v1/users/{user_id}/unlock', { params: { path: { user_id: props.user.id } } }))
    emit('saved', `${props.user.username} unlocked.`)
  } catch (err) {
    error.value = failure(err, 'The user was not unlocked.')
  } finally {
    acting.value = null
  }
}

// Deleting asks with the browser's confirm(), as in CatherIs Platform (ADR-0028, fifth amendment).
async function remove(): Promise<void> {
  if (!window.confirm(`Delete ${props.user.username}? Their audit history stays under their username.`)) return
  acting.value = 'delete'
  error.value = null
  try {
    await unwrap(api.DELETE('/api/v1/users/{user_id}', { params: { path: { user_id: props.user.id } } }))
    emit('saved', `${props.user.username} deleted.`)
  } catch (err) {
    error.value = failure(err, 'The user was not deleted.')
  } finally {
    acting.value = null
  }
}
</script>

<template>
  <AppModal :title="who" :description="`Added on ${props.user.created_at.slice(0, 10)}`" :dirty="dirty || !!password" @close="emit('close')">
    <form id="edit-user" class="form" @submit.prevent="save">
      <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
      <div class="field">
        <span class="lbl">Username</span>
        <span class="mono">{{ props.user.username }}</span>
      </div>
      <div class="field">
        <label class="lbl" for="eu-display">Display name</label>
        <input id="eu-display" v-model.trim="displayName" class="input" maxlength="100" autocomplete="off">
      </div>
      <div v-if="sso" class="field">
        <span class="lbl">Signs in with</span>
        <span>Single sign-on. Their email address is their username.</span>
      </div>
      <div v-else class="field">
        <label class="lbl" for="eu-email">Email address <span class="opt">optional</span></label>
        <input id="eu-email" v-model.trim="email" class="input" type="email" maxlength="254" autocomplete="off" spellcheck="false" aria-describedby="eu-email-h">
        <span id="eu-email-h" class="cap">Only admins see it. Argus sends no mail, and they still sign in with their username.</span>
      </div>
      <RoleCards v-model="role" name="edit-role" :disabled="locked || sso" />
      <span v-if="sso" class="cap lock">
        <AppIcon name="info" :size="14" />Comes from their identity provider's groups at each sign-in<template v-if="props.user.role_group">, now group <span class="mono">{{ props.user.role_group }}</span></template>.
      </span>
      <div class="field">
        <span class="lbl">Sign-in</span>
        <SwitchToggle v-model="active" :label="`Sign-in for ${props.user.username}`" :disabled="locked" />
        <span class="cap">Inactive users can't sign in. Their history stays.</span>
      </div>
      <span v-if="locked" class="cap lock"><AppIcon name="info" :size="14" />{{ lockReason }}</span>
    </form>

    <div class="actions">
      <div v-if="!isMe && !sso" class="action">
        <template v-if="settingPassword">
          <SecretField v-model="password" label="New password" :error="passwordError" help="Ends their sessions. They choose their own at the next sign-in." allow-generate />
          <div class="row">
            <button type="button" class="btn btn-secondary btn-sm" :disabled="acting !== null || !password" @click="setPassword">
              <AppIcon v-if="acting === 'password'" name="spinner" :size="14" :stroke="2.4" />Set password
            </button>
            <button type="button" class="btn btn-ghost btn-sm" @click="settingPassword = false; password = ''">Cancel</button>
          </div>
        </template>
        <template v-else>
          <button type="button" class="btn btn-secondary btn-sm" @click="settingPassword = true">Set a new password</button>
          <span class="cap">Ends their sessions. They choose their own at the next sign-in.</span>
        </template>
      </div>
      <div v-if="props.user.locked && !sso" class="action">
        <button type="button" class="btn btn-secondary btn-sm" :disabled="acting !== null" @click="unlock">
          <AppIcon v-if="acting === 'unlock'" name="spinner" :size="14" :stroke="2.4" />Unlock
        </button>
        <span class="cap">Clears the failed sign-ins that locked this username.</span>
      </div>
      <div v-if="!props.user.is_active" class="action">
        <button type="button" class="btn btn-danger btn-sm" :disabled="acting !== null" @click="remove">
          <AppIcon v-if="acting === 'delete'" name="spinner" :size="14" :stroke="2.4" />Delete user
        </button>
        <span v-if="sso" class="cap">Deleting an SSO user lets them back in at their next sign-in, as a new user. Deactivate to keep them out.</span>
      </div>
    </div>

    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">Cancel</button>
      <button type="submit" form="edit-user" class="btn btn-primary" :disabled="saving || !dirty">
        <AppIcon v-if="saving" name="spinner" :size="16" :stroke="2.4" />{{ saving ? 'Saving…' : 'Save' }}
      </button>
    </template>
  </AppModal>
</template>

<style scoped>
.opt {
  font-weight: 400;
  color: var(--text-3);
}

.form {
  display: flex;
  flex-direction: column;
  gap: var(--s-16);
}

.lock {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.actions {
  display: flex;
  flex-direction: column;
  gap: var(--s-14);
  margin-top: var(--s-16);
  padding-top: var(--s-16);
  border-top: 1px solid var(--border);
}

.action {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--s-6);
}

.action :deep(.field) {
  align-self: stretch;
}

.row {
  display: flex;
  gap: var(--s-8);
}
</style>
