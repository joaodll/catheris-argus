<script setup lang="ts">
/**
 * Changing your own password (PUT /auth/password; docs/ui/screens.md, E1 Choose a new password
 * and E13 Change your password): current, new and repeated, checked before sending. The submit
 * button is the caller's (`form` = `formId`); `busy` tells it when to disable it.
 */
import { ref } from 'vue'
import { api, messageOf } from '@/api/client'
import { username } from '@/composables/useSession'
import { PASSWORD_HELP, apiPasswordProblem, newPasswordProblem, type PasswordField } from '@/passwords'
import AlertBanner from './AlertBanner.vue'
import PasswordInput from './PasswordInput.vue'

const props = defineProps<{ formId: string }>()
const emit = defineEmits<{ changed: []; 'update:busy': [busy: boolean] }>()

const current = ref('')
const next = ref('')
const repeat = ref('')
const errors = ref<Partial<Record<PasswordField, string>>>({})
const error = ref<string | null>(null)
const currentInput = ref<InstanceType<typeof PasswordInput> | null>(null)

async function submit(): Promise<void> {
  error.value = null
  const problem = newPasswordProblem(next.value, repeat.value, username.value ?? '')
  errors.value = problem ? { [problem.field]: problem.message } : {}
  if (problem) return
  emit('update:busy', true)
  try {
    const { response, error: body } = await api.PUT('/api/v1/auth/password', {
      body: { current_password: current.value, new_password: next.value },
    })
    if (response.status === 204) {
      current.value = next.value = repeat.value = ''
      emit('changed')
      return
    }
    if (response.status === 429) {
      const minutes = Math.round(Number(response.headers.get('Retry-After') ?? '900') / 60)
      error.value = `Too many wrong attempts. Try again in ${minutes} minutes.`
    } else if (response.status === 422) {
      const found = apiPasswordProblem(messageOf(422, body))
      errors.value = { [found.field]: found.message }
      if (found.field === 'current') {
        current.value = ''
        currentInput.value?.focus()
      }
    } else {
      error.value = messageOf(response.status, body)
    }
  } catch {
    error.value = "Argus can't reach its API."
  } finally {
    emit('update:busy', false)
  }
}
</script>

<template>
  <form :id="props.formId" class="form" novalidate @submit.prevent="submit">
    <AlertBanner v-if="error" kind="fail">{{ error }}</AlertBanner>
    <div class="field">
      <label class="lbl" :for="`${props.formId}-current`">Current password</label>
      <PasswordInput
        :id="`${props.formId}-current`"
        ref="currentInput"
        v-model="current"
        autocomplete="current-password"
        :invalid="!!errors.current"
        :describedby="errors.current ? `${props.formId}-current-e` : undefined"
      />
      <span v-if="errors.current" :id="`${props.formId}-current-e`" class="field-error">{{ errors.current }}</span>
    </div>
    <div class="field">
      <label class="lbl" :for="`${props.formId}-new`">New password</label>
      <PasswordInput
        :id="`${props.formId}-new`"
        v-model="next"
        autocomplete="new-password"
        :invalid="!!errors.new"
        :describedby="`${props.formId}-new-h`"
      />
      <span v-if="errors.new" class="field-error">{{ errors.new }}</span>
      <span :id="`${props.formId}-new-h`" class="cap">{{ PASSWORD_HELP }}</span>
    </div>
    <div class="field">
      <label class="lbl" :for="`${props.formId}-repeat`">Repeat new password</label>
      <PasswordInput
        :id="`${props.formId}-repeat`"
        v-model="repeat"
        autocomplete="new-password"
        :invalid="!!errors.repeat"
        :describedby="errors.repeat ? `${props.formId}-repeat-e` : undefined"
      />
      <span v-if="errors.repeat" :id="`${props.formId}-repeat-e`" class="field-error">{{ errors.repeat }}</span>
    </div>
  </form>
</template>

<style scoped>
.form {
  display: flex;
  flex-direction: column;
  gap: 15px;
}
</style>
