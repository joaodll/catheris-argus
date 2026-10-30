<script setup lang="ts">
/** Choose a new password (docs/ui/screens.md, E1): after signing in with a password an admin
 * set, every page waits for this one (the router sends the user here). */
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AuthCard from '@/components/AuthCard.vue'
import PasswordChangeForm from '@/components/PasswordChangeForm.vue'
import { refreshSession, signOut } from '@/composables/useSession'
import { toast } from '@/composables/useToasts'

const route = useRoute()
const router = useRouter()
const busy = ref(false)

/** Only same-app paths: never an open redirect. */
function nextPath(): string {
  const next = route.query.next
  return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/'
}

async function changed(): Promise<void> {
  await refreshSession()
  toast('Password changed.')
  await router.replace(nextPath())
}

async function leave(): Promise<void> {
  await signOut()
  await router.push({ name: 'sign-in', query: { reason: 'signed-out' } })
}
</script>

<template>
  <AuthCard>
    <h1 data-page-title tabindex="-1">Choose a new password</h1>
    <p class="sub">An administrator set your password. Choose your own to continue.</p>
    <PasswordChangeForm v-model:busy="busy" form-id="new-password" @changed="changed" />
    <button class="btn btn-primary btn-lg full" type="submit" form="new-password" :disabled="busy">
      <span v-if="busy" class="spinner" aria-hidden="true"></span>{{ busy ? 'Saving…' : 'Save and continue' }}
    </button>
    <button type="button" class="btn btn-ghost center" @click="leave">Sign out</button>
  </AuthCard>
</template>

<style scoped>
.full {
  width: 100%;
}
</style>
