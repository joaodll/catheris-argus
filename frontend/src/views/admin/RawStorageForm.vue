<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import AppIcon from '@/components/AppIcon.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useDirtyGuard } from '@/composables/useDirtyGuard'
import { toast } from '@/composables/useToasts'
import SettingsCard from './SettingsCard.vue'
import { checkRawStorage, normalized, type FieldErrors, type Tool } from './rawStorage'

const TOOLS: { tool: Tool; name: string }[] = [
  { tool: 'steampipe', name: 'Steampipe' },
  { tool: 'prowler', name: 'Prowler' },
  { tool: 'cloudfox', name: 'CloudFox' },
]

const props = defineProps<{ settings: Schemas['SettingsOut'] }>()
const emit = defineEmits<{ saved: [settings: Schemas['SettingsOut']] }>()

function fromSettings(): { bucket: string; region: string; prefixes: Record<Tool, string> } {
  const { bucket, region, prefixes } = props.settings.raw_storage
  // The API always returns all three; the schema marks them optional because they have defaults.
  const folder = (tool: Tool): string => prefixes?.[tool] ?? ''
  return {
    bucket: bucket ?? '',
    region: region ?? '',
    prefixes: { steampipe: folder('steampipe'), prowler: folder('prowler'), cloudfox: folder('cloudfox') },
  }
}

const saved = ref(fromSettings())
const form = ref(fromSettings())
// Only when this topic's values change: another card's save must not discard edits here.
watch(() => JSON.stringify(props.settings.raw_storage), () => {
  saved.value = fromSettings()
  form.value = fromSettings()
})
const dirty = computed(() => JSON.stringify(form.value) !== JSON.stringify(saved.value))
useDirtyGuard(dirty)
const configured = computed(() => props.settings.raw_storage.bucket != null)

const saving = ref(false)
const error = ref<string | null>(null)
// Shown once a save was tried, then kept current as the fields change.
const tried = ref(false)
const fieldErrors = computed<FieldErrors>(() => (tried.value ? checkRawStorage(normalized(form.value)) : {}))

async function save(): Promise<void> {
  tried.value = true
  error.value = null
  const body = normalized(form.value)
  if (Object.keys(checkRawStorage(body)).length) {
    error.value = 'Raw output storage was not saved: fix the fields marked above.'
    return
  }
  form.value = body
  saving.value = true
  try {
    const result = await unwrap(
      api.PUT('/api/v1/settings/raw-storage', {
        body: { bucket: body.bucket || null, region: body.region || null, prefixes: body.prefixes },
      }),
    )
    tried.value = false
    emit('saved', result)
    toast('Raw output storage saved. The change is in the audit log.')
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'Raw output storage was not saved.'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <SettingsCard
    id="raw-storage"
    title="Raw output storage"
    description="Where AWS scans keep each tool's raw output. Demo connections always use the local disk."
    :dirty="dirty"
    :saving="saving"
    :error="error"
    save-label="Save storage"
    @save="save"
    @discard="form = fromSettings(); tried = false; error = null"
  >
    <StatusBadge v-if="configured" class="state" status="set" label="Bucket set" />
    <StatusBadge v-else class="state" status="warning" label="Not set: AWS scans can't run" />
    <div class="form-grid">
      <div class="field">
        <label class="lbl" for="rs-bucket">S3 bucket</label>
        <input id="rs-bucket" v-model.trim="form.bucket" class="input mono" autocomplete="off" spellcheck="false" placeholder="my-argus-raw" :aria-invalid="fieldErrors.bucket ? 'true' : undefined" :aria-describedby="fieldErrors.bucket ? 'rs-bucket-err rs-bucket-help' : 'rs-bucket-help'">
        <span v-if="fieldErrors.bucket" id="rs-bucket-err" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ fieldErrors.bucket }}</span>
        <span id="rs-bucket-help" class="cap">Argus uses the bucket's default encryption and reports it on every run.</span>
      </div>
      <div class="field">
        <label class="lbl" for="rs-region">Region</label>
        <input id="rs-region" v-model.trim="form.region" class="input mono" autocomplete="off" spellcheck="false" placeholder="eu-west-1" :aria-invalid="fieldErrors.region ? 'true' : undefined" :aria-describedby="fieldErrors.region ? 'rs-region-err rs-region-help' : 'rs-region-help'">
        <span v-if="fieldErrors.region" id="rs-region-err" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ fieldErrors.region }}</span>
        <span id="rs-region-help" class="cap">The bucket's region. Leave both empty to turn S3 off.</span>
      </div>
    </div>
    <fieldset class="folders">
      <legend class="lbl">Folder per tool</legend>
      <div class="form-grid">
        <div v-for="t in TOOLS" :key="t.tool" class="field">
          <label class="lbl" :for="`rs-${t.tool}`">{{ t.name }}</label>
          <input :id="`rs-${t.tool}`" v-model.trim="form.prefixes[t.tool]" class="input mono" autocomplete="off" spellcheck="false" :aria-invalid="fieldErrors[t.tool] ? 'true' : undefined" :aria-describedby="fieldErrors[t.tool] ? `rs-${t.tool}-err rs-${t.tool}-help` : `rs-${t.tool}-help`">
          <span v-if="fieldErrors[t.tool]" :id="`rs-${t.tool}-err`" class="field-error"><AppIcon name="warning" :size="14" :stroke="2.2" />{{ fieldErrors[t.tool] }}</span>
          <span :id="`rs-${t.tool}-help`" class="cap mono path">{{ form.prefixes[t.tool] || '…' }}/aws/&lt;account&gt;/&lt;date&gt;/&lt;run&gt;/</span>
        </div>
      </div>
    </fieldset>
    <AlertBanner kind="info">
      Use SSE-KMS as the bucket's default encryption. Raw output can hold secret values (Lambda environment, EC2 user data,
      CloudFox env-vars), and SSE-KMS adds a key policy and a decrypt audit trail that SSE-S3 does not. Argus stores
      whatever the bucket's default is and flags runs stored without KMS in Runs. Use a bucket for Argus alone: raw output
      maps the whole account.
    </AlertBanner>
    <span class="cap">The platform identity below writes here. Its policy should allow s3:PutObject on this bucket only, plus the KMS key's GenerateDataKey.</span>
  </SettingsCard>
</template>

<style scoped>
.state {
  align-self: flex-start;
}

.folders {
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
}

.path {
  overflow-wrap: anywhere;
}
</style>
