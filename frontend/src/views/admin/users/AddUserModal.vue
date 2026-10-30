<script setup lang="ts">
/** Add user (POST /users; docs/ui/screens.md, E13). The password is set once here; the user
 * chooses their own at the first sign-in. */
import { computed, ref } from 'vue'
import { ApiError, api, unwrap } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppModal from '@/components/AppModal.vue'
import SecretField from '@/components/SecretField.vue'
import { ROLE_LABEL, type Role } from '@/composables/useSession'
import { newPasswordProblem } from '@/passwords'
import RoleCards from './RoleCards.vue'

const emit = defineEmits<{ close: []; saved: [message: string] }>()

const username = ref('')
const displayName = ref('')
const role = ref<Role>('viewer')
const password = ref('')
const saving = ref(false)
const error = ref<string | null>(null)
const passwordError = ref<string | null>(null)
const dirty = computed(() => !!(username.value || displayName.value || password.value))

async function save(): Promise<void> {
  error.value = null
  passwordError.value = newPasswordProblem(password.value, password.value, username.value)?.message ?? null
  if (passwordError.value) return
  saving.value = true
  try {
    const created = await unwrap(
      api.POST('/api/v1/users', {
        body: { username: username.value, display_name: displayName.value, role: role.value, password: password.value },
      }),
    )
    emit('saved', `${created.username} added as ${ROLE_LABEL[created.role]}. Give them the password over a channel you trust.`)
  } catch (err) {
    error.value =
      err instanceof ApiError && err.status === 409
        ? `There is a user called ${username.value.toLowerCase()} already.`
        : err instanceof ApiError
          ? err.message
          : 'The user was not added.'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <AppModal title="Add user" description="They sign in with this password once, then choose their own." :dirty="dirty" @close="emit('close')">
    <form id="add-user" class="form" @submit.prevent="save">
      <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
      <div class="field">
        <label class="lbl" for="u-name">Username</label>
        <input id="u-name" v-model.trim="username" class="input mono" required minlength="3" maxlength="64" autocomplete="off" spellcheck="false" aria-describedby="u-name-h">
        <span id="u-name-h" class="cap">Lowercase letters, digits, dot, dash and underscore; 3 to 64. It can't be changed later.</span>
      </div>
      <div class="field">
        <label class="lbl" for="u-display">Display name <span class="opt">optional</span></label>
        <input id="u-display" v-model.trim="displayName" class="input" maxlength="100" autocomplete="off">
      </div>
      <RoleCards v-model="role" name="add-role" />
      <SecretField
        v-model="password"
        label="Password"
        help="They choose their own at the first sign-in."
        :error="passwordError"
        allow-generate
      />
    </form>
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">Cancel</button>
      <button type="submit" form="add-user" class="btn btn-primary" :disabled="saving || !username || !password">
        <AppIcon v-if="saving" name="spinner" :size="16" :stroke="2.4" />{{ saving ? 'Adding…' : 'Add user' }}
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

.opt {
  font-weight: 400;
  color: var(--text-3);
}
</style>
