<script setup lang="ts">
/** Change your password, from the shell's user block (docs/ui/screens.md, E13). This session
 * stays; the others end. */
import { ref } from 'vue'
import { toast } from '@/composables/useToasts'
import AppIcon from './AppIcon.vue'
import AppModal from './AppModal.vue'
import PasswordChangeForm from './PasswordChangeForm.vue'

const emit = defineEmits<{ close: [] }>()
const busy = ref(false)

function changed(): void {
  toast('Password changed. Your other sessions were signed out.')
  emit('close')
}
</script>

<template>
  <AppModal title="Change password" description="Your other sessions are signed out when you change it." @close="emit('close')">
    <PasswordChangeForm v-model:busy="busy" form-id="change-password" @changed="changed" />
    <template #footer>
      <button type="button" class="btn btn-secondary" @click="emit('close')">Cancel</button>
      <button type="submit" form="change-password" class="btn btn-primary" :disabled="busy">
        <AppIcon v-if="busy" name="spinner" :size="16" :stroke="2.4" />{{ busy ? 'Changing…' : 'Change password' }}
      </button>
    </template>
  </AppModal>
</template>
