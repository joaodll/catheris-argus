<script setup lang="ts">
import { computed, onScopeDispose, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AuthCard from '@/components/AuthCard.vue'
import PasswordInput from '@/components/PasswordInput.vue'
import { refreshSession } from '@/composables/useSession'

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

const notice = computed(() => {
  if (route.query.reason === 'expired') return 'Your session ended. Sign in again.'
  if (route.query.reason === 'signed-out') return 'You signed out.'
  return null
})
const locked = computed(() => lockedUntil.value !== null && lockedUntil.value > now.value)
const unlockAt = computed(() => (lockedUntil.value ? new Date(lockedUntil.value).toISOString().slice(11, 16) : ''))

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
      error.value = `Too many attempts. Try again in ${Math.round(seconds / 60)} minutes.`
    } else if (response.status === 401) {
      error.value = 'Wrong username or password.'
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
    <p class="sub">Cloud security posture, attack paths and inventory</p>

    <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
    <AlertBanner v-else-if="notice">{{ notice }}</AlertBanner>
    <form class="form" novalidate @submit.prevent="submit">
      <div class="field">
        <label class="lbl" for="username">Username</label>
        <input id="username" v-model="name" class="input" name="username" autocomplete="username" required :readonly="busy">
      </div>
      <div class="field">
        <label class="lbl" for="password">Password</label>
        <PasswordInput id="password" ref="passwordInput" v-model="password" autocomplete="current-password" :readonly="busy" />
      </div>
      <button class="btn btn-primary btn-lg full" type="submit" :disabled="busy || locked || !name || !password">
        <span v-if="busy" class="spinner" aria-hidden="true"></span>{{ busy ? 'Signing in…' : 'Sign in' }}
      </button>
      <span v-if="locked" class="cap center">You can try again at <span class="mono">{{ unlockAt }}</span> UTC.</span>
    </form>
    <template #below>
      <p class="cap center">
        Reachable only inside the cluster network until SSO. You are signed out after 30 minutes idle and 12 hours in total.
      </p>
    </template>
  </AuthCard>
</template>

<style scoped>
.full {
  width: 100%;
  margin-top: 5px;
}
</style>
