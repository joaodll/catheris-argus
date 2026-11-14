<script setup lang="ts">
/**
 * The Tag filter (migration 0051; spec in the palace, frontend/27ceefe0): choose a tag name, then its
 * values. A name with too many values to list takes one typed exactly. Values of one name are
 * OR, names are AND. Shared by Misconfigurations, Vulnerabilities and New report; each passes
 * the names its list offers (its facets), and the values come from that list's tag-values route.
 * A masked value is never offered (the server leaves it out).
 */
import { computed, ref, watch } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import MultiSelect, { type MultiOption } from '@/components/MultiSelect.vue'
import { useResource } from '@/composables/useResource'
import TagChips from './TagChips.vue'
import { TAG_VALUE_MAX, type TagPair, byName, withValues } from './tagFilter'

const props = withDefaults(
  defineProps<{
    id: string
    list: 'misconfigurations' | 'vulnerabilities'
    names: Schemas['TagKeyOut'][] | null
    status: 'ready' | 'loading' | 'error'
    connectionIds: number[]
    modelValue: TagPair[]
    // The chips inside the field (New report); a list shows them in its filter bar instead.
    chips?: boolean
  }>(),
  { chips: false },
)
const emit = defineEmits<{ 'update:modelValue': [TagPair[]] }>()

const name = ref('')
const chosen = computed(() => props.names?.find((n) => n.key === name.value) ?? null)
const current = computed(() => byName(props.modelValue).find((g) => g.key === name.value)?.values ?? [])

const connectionKey = computed(() => props.connectionIds.join(','))
const values = useResource(
  async () => {
    if (!chosen.value?.listed) return null
    const query = { key: chosen.value.key, connection_id: props.connectionIds }
    const body =
      props.list === 'misconfigurations'
        ? await unwrap(api.GET('/api/v1/findings/tag-values', { params: { query } }))
        : await unwrap(api.GET('/api/v1/vulnerabilities/tag-values', { params: { query } }))
    return body
  },
  { watch: [name, connectionKey, () => props.list] },
)
const valueStatus = computed(() => (values.error.value ? 'error' : values.data.value ? 'ready' : 'loading'))
// A chosen value stays an option even when the list no longer offers it, so it can be removed.
const valueOptions = computed<MultiOption[]>(() =>
  [...new Set([...current.value, ...(values.data.value?.values ?? [])])].map((v) => ({ value: v, label: v })),
)
// Too many to list (the name lists none), or more than the list shows: a value is typed.
const typedHelp = computed(() =>
  chosen.value?.listed ? 'More values than listed: type one exactly.' : 'Too many values to list: type one exactly.',
)
const typable = computed(() => Boolean(chosen.value && (!chosen.value.listed || values.data.value?.more)))

function setValues(next: string[]): void {
  emit('update:modelValue', withValues(props.modelValue, name.value, next))
}

const typed = ref('')
watch(name, () => (typed.value = ''))
function addTyped(): void {
  const value = typed.value.trim()
  if (!value) return
  setValues([...current.value, value])
  typed.value = ''
}

const nameSummary = computed(() => {
  if (props.status === 'loading') return 'Loading…'
  if (props.status === 'error') return "Couldn't load tags"
  if (!props.names?.length) return 'No tags in this list'
  return 'Choose a name'
})
const namesReady = computed(() => props.status === 'ready' && Boolean(props.names?.length))
</script>

<template>
  <fieldset class="field tag-filter">
    <legend class="lbl">Tag</legend>
    <div v-if="chips && modelValue.length" class="chips">
      <TagChips :model-value="modelValue" @update:model-value="emit('update:modelValue', $event)" />
    </div>
    <div class="row">
      <div class="field">
        <label class="lbl" :for="`${id}-name`">Tag name</label>
        <select :id="`${id}-name`" v-model="name" class="select" :disabled="!namesReady">
          <option value="">{{ nameSummary }}</option>
          <option v-for="n in names ?? []" :key="n.key" :value="n.key">{{ n.key }}</option>
        </select>
      </div>
      <MultiSelect
        v-if="chosen?.listed"
        :id="`${id}-values`"
        label="Values"
        :options="valueOptions"
        :status="valueStatus"
        :model-value="current"
        @update:model-value="setValues"
      />
      <div v-if="typable" class="field">
        <label class="lbl" :for="`${id}-exact`">Exact value</label>
        <span class="exact">
          <input
            :id="`${id}-exact`"
            v-model="typed"
            class="input"
            type="text"
            :maxlength="TAG_VALUE_MAX"
            autocomplete="off"
            :aria-describedby="`${id}-exact-help`"
            @keydown.enter.prevent="addTyped"
          >
          <button type="button" class="btn btn-secondary btn-sm" :disabled="!typed.trim()" @click="addTyped">Add</button>
        </span>
        <span :id="`${id}-exact-help`" class="cap">{{ typedHelp }}</span>
      </div>
    </div>
    <span class="cap">Values of one name match any of them; different names must all match. Findings on resources that are not in the inventory have no tags.</span>
  </fieldset>
</template>

<style scoped>
.tag-filter {
  min-width: 0;
  margin: 0;
  padding: 0;
  border: 0;
}

.row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-12);
  align-items: flex-end;
}

.row .select {
  max-width: 260px;
}

.exact {
  display: flex;
  gap: var(--s-8);
  align-items: center;
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-8);
}

.cap {
  max-width: 60ch;
}

@media (max-width: 640px) {
  .row {
    flex-direction: column;
    align-items: stretch;
  }

  .row .select {
    max-width: none;
  }
}
</style>
