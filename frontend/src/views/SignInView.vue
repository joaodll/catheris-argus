<script setup lang="ts">
import { computed, onMounted, onScopeDispose, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AuthCard from '@/components/AuthCard.vue'
import PasswordInput from '@/components/PasswordInput.vue'
import { apiUnreachable, refreshSession } from '@/composables/useSession'
import { waitTime } from '@/format'

const route = useRoute()
const router = useRouter()

const name = ref('')
const password = ref('')
const busy = ref(false)
const error = ref<string | null>(null)
const lockedUntil = ref<number | null>(null)
const now = ref(Date.now())
const passwordInput = ref<InstanceType<typeof PasswordInput> | null>(null)
const tick = window.setInterval(() => (now.value = Date.now()), 1000)
onScopeDispose(() => window.clearInterval(tick))

// Which sign-ins this install offers (ADR-0048). Until the answer comes, the password form shows,
// as it always did.
const methods = ref<{ local: boolean; sso: boolean }>({ local: true, sso: false })
onMounted(async () => {
  try {
    const { data } = await api.GET('/api/v1/auth/methods')
    if (data) methods.value = data
  } catch {
    // The notice below says the API can't be reached.
  }
})

// An SSO sign-in that came back refused: a fixed sentence per reason, never the IdP's words.
const SSO_REFUSED: Record<string, string> = {
  'sso-no-group': 'Your account is in no group that grants access to Argus. Ask whoever manages your identity provider.',
  'sso-inactive': 'Your Argus account is deactivated. Ask an Argus admin.',
  'sso-conflict': 'Your email address belongs to another Argus user. Ask an Argus admin.',
  'sso-expired': 'The answer from your identity provider had expired. Sign in again.',
  'sso-state': 'Your sign-in took too long, or began in another browser. Start again.',
  'sso-nameid': "Your identity provider sends an identifier Argus can't use. Ask whoever manages it.",
  'sso-idp-refused': "Your identity provider didn't sign you in.",
  'sso-off': 'Single sign-on is off on this install.',
}
const ssoReason = computed(() => {
  const reason = route.query.reason
  return typeof reason === 'string' && reason.startsWith('sso-') ? reason : null
})
const ssoBusy = computed(() => ssoReason.value === 'sso-busy')
const ssoError = computed(() => {
  if (!ssoReason.value || ssoBusy.value) return null
  return SSO_REFUSED[ssoReason.value] ?? "Argus couldn't verify the answer from your identity provider. Start again."
})
const ssoHref = computed(() => {
  const next = nextPath()
  return next === '/' ? '/api/v1/auth/saml/login' : `/api/v1/auth/saml/login?${new URLSearchParams({ next })}`
})

const notice = computed(() => {
  if (apiUnreachable.value) return "Argus can't reach its API right now. Sign in once it is back."
  if (route.query.reason === 'expired') return 'Your session ended. Sign in again.'
  if (route.query.reason === 'signed-out') return 'You signed out.'
  if (ssoBusy.value) return 'Argus is busy signing people in. Try again in a moment.'
  return null
})
const locked = computed(() => lockedUntil.value !== null && lockedUntil.value > now.value)
const unlockAt = computed(() => (lockedUntil.value ? new Date(lockedUntil.value).toISOString().slice(11, 16) : ''))
// Under a minute, a clock time says nothing the error doesn't.
const longLock = computed(() => locked.value && (lockedUntil.value as number) - now.value >= 60_000)

/** Only same-app paths: never an open redirect. */
function nextPath(): string {
  const next = route.query.next
  return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/'
}

async function submit(): Promise<void> {
  if (busy.value || locked.value) return
  busy.value = true
  error.value = null
  try {
    const { response } = await api.POST('/api/v1/auth/sign-in', {
      body: { username: name.value, password: password.value },
    })
    if (response.status === 204) {
      password.value = ''
      await refreshSession()
      await router.replace(nextPath())
      return
    }
    if (response.status === 429) {
      const seconds = Number(response.headers.get('Retry-After') ?? '900')
      lockedUntil.value = Date.now() + seconds * 1000
      error.value = `Too many attempts. Try again in ${waitTime(seconds)}.`
    } else if (response.status === 401) {
      error.value = 'Wrong username or password.'
    } else if (response.status === 502 || response.status === 504) {
      error.value = "Argus can't reach its API. Try again in a moment."
    } else {
      error.value = 'Argus had a problem signing you in. Try again in a moment.'
    }
  } catch {
    error.value = "Argus can't reach its API."
  } finally {
    busy.value = false
  }
  password.value = ''
  passwordInput.value?.focus()
}
</script>

<template>
  <AuthCard>
    <h1 data-page-title tabindex="-1">Sign in to continue</h1>
    <p class="sub">Cloud security posture, vulnerabilities and inventory</p>

    <AlertBanner v-if="error || ssoError" kind="fail">{{ error || ssoError }}</AlertBanner>
    <AlertBanner v-else-if="notice" :kind="ssoBusy ? 'warn' : 'info'">{{ notice }}</AlertBanner>
    <template v-if="methods.sso">
      <a class="btn btn-primary btn-lg full" :href="ssoHref">Sign in with SSO</a>
      <p v-if="methods.local" class="or cap" aria-hidden="true"><span>or with a password</span></p>
      <p v-else class="cap center">Password sign-in is off on this install.</p>
    </template>
    <form v-if="methods.local" class="form" novalidate :aria-label="methods.sso ? 'Sign in with a password' : undefined" @submit.prevent="submit">
      <div class="field">
        <label class="lbl" for="username">Username</label>
        <input id="username" v-model="name" class="input" name="username" autocomplete="username" required :readonly="busy">
      </div>
      <div class="field">
        <label class="lbl" for="password">Password</label>
        <PasswordInput id="password" ref="passwordInput" v-model="password" autocomplete="current-password" :readonly="busy" />
      </div>
      <button class="btn btn-lg full" :class="methods.sso ? 'btn-secondary' : 'btn-primary'" type="submit" :disabled="busy || locked || !name || !password">
        <span v-if="busy" class="spinner" aria-hidden="true"></span>{{ busy ? 'Signing in…' : 'Sign in' }}
      </button>
      <span v-if="longLock" class="cap center">You can try again at <span class="mono">{{ unlockAt }}</span> UTC.</span>
    </form>
    <template #below>
      <p class="cap center">
        <template v-if="!methods.sso">Keep Argus inside your network until single sign-on is set up. </template>You are signed out after 30 minutes idle and 12 hours in total.
      </p>
    </template>
  </AuthCard>
</template>

<style scoped>
.full {
  width: 100%;
  margin-top: 5px;
}
/* "or with a password", between two rules. */
.or {
  display: flex;
  align-items: center;
  gap: var(--s-8);
  margin: var(--s-16) 0 0;
}
.or::before,
.or::after {
  content: '';
  flex: 1;
  border-top: 1px solid var(--border);
}
</style>
