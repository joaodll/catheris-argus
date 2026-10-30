<script setup lang="ts">
/**
 * A finding's details row (docs/ui/screens.md, E7): what the tool says is wrong with this
 * resource, the facts, then what it says about the check: risk, description, how to fix it
 * (text, code to copy, links). The list row is shown at once; the tool's text loads with
 * GET /findings/{id}. Remediation code is for a human to apply: Argus never runs it. A finding
 * with a reach says Argus's own verdict under the tool's (ADR-0035, sixth amendment) and links
 * to the evidence on the resource sheet, never copying it.
 */
import { computed } from 'vue'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import CopyButton from '@/components/CopyButton.vue'
import CommandsBlock from './CommandsBlock.vue'
import { useResource } from '@/composables/useResource'
import { categoryLabel } from './findingFilters'
import { regionLabel, webUrl } from './labels'
import ToolText from './ToolText.vue'
import { CODE_KINDS, codeBody } from './toolText'
import ReachBadge from './ReachBadge.vue'
import { hasEvidence, reasonWords, toolNote } from './reachReason'

const props = defineProps<{
  finding: Schemas['FindingOut']
  // Already loaded (a finding's own link): no second request.
  preloaded?: Schemas['FindingDetail'] | null
  // The "Open in new tab" link; hidden on the finding's own page.
  ownLink?: boolean
}>()

const fetched = useResource(async () =>
  props.preloaded ? props.preloaded : await unwrap(api.GET('/api/v1/findings/{finding_id}', { params: { path: { finding_id: props.finding.id } } })),
)
const detail = computed(() => fetched.data.value)
const f = computed(() => props.finding)

const guide = computed(() => webUrl(f.value.remediation_url))
// Every other link the tool gives, each once, the guide left out.
const links = computed(() =>
  (detail.value?.links ?? []).map((l) => webUrl(l)).filter((l): l is string => l != null && l !== guide.value),
)
const code = computed(() =>
  CODE_KINDS.flatMap((k) => {
    const value = detail.value?.remediation_code[k.key]
    return value ? [{ ...k, ...codeBody(value) }] : []
  }),
)
const consoleSteps = computed(() => detail.value?.remediation_code.other ?? null)
// Argus's verdict on the resource: its reason in words, why the tools differ, where the evidence is.
const verdict = computed(() => {
  const reach = f.value.reach
  if (!reach) return null
  const evidence = f.value.resource_id != null && hasEvidence(reach, f.value.reach_reason)
  return {
    reason: reasonWords(reach, f.value.reach_reason),
    note: toolNote(f.value.tool, reach),
    evidence: evidence ? { name: 'resources', query: { open: String(f.value.resource_id) }, hash: '#from-internet' } : null,
  }
})
</script>

<template>
  <div class="detail-body">
    <h3 class="h2 full-title">{{ f.title }}</h3>
    <RouterLink
      v-if="ownLink"
      class="btn btn-ghost btn-sm own-link"
      :to="{ name: 'findings', query: { finding: String(f.id) } }"
      target="_blank"
      :aria-label="`Open ${f.title} in a new tab`"
    >
      Open in new tab ↗
    </RouterLink>
    <AlertBanner v-if="f.state === 'reopened'" kind="info">
      Resolved{{ f.resolved_on ? ` on ${f.resolved_on}` : '' }}, then seen again. Counted as a regression.
    </AlertBanner>
    <section v-if="detail?.detail" class="block" aria-label="What the tool found">
      <span class="lbl">What the tool found</span>
      <p class="said">{{ detail.detail }}</p>
    </section>
    <section v-if="verdict" class="block" aria-labelledby="verdict-h">
      <span id="verdict-h" class="lbl">Argus's verdict</span>
      <ReachBadge :reach="f.reach" :reason="f.reach_reason" />
      <p class="said reason" :class="{ mono: verdict.reason.mono }">{{ verdict.reason.text }}</p>
      <p v-if="verdict.note" class="cap">{{ verdict.note }}</p>
      <RouterLink v-if="verdict.evidence" class="btn btn-secondary btn-sm evidence-link" :to="verdict.evidence">See the evidence</RouterLink>
    </section>

    <dl class="facts">
      <div><dt class="lbl">Check</dt><dd class="mono">{{ f.check_id }}</dd></div>
      <div><dt class="lbl">Result</dt><dd class="mono">{{ f.status }}</dd></div>
      <div>
        <dt class="lbl">Service</dt>
        <dd v-if="f.service" class="mono">{{ f.service }}</dd>
        <dd v-else class="cap">Not recorded</dd>
      </div>
      <div>
        <dt class="lbl">Resource type</dt>
        <dd v-if="f.resource_type" class="mono">{{ f.resource_type }}</dd>
        <dd v-else class="cap">Not recorded</dd>
      </div>
      <div>
        <dt class="lbl">Categories</dt>
        <dd v-if="f.categories.length" class="cats">
          <span v-for="c in f.categories" :key="c" class="chip">{{ categoryLabel(c) }}</span>
        </dd>
        <dd v-else class="cap">Not recorded</dd>
      </div>
      <div><dt class="lbl">Region</dt><dd class="mono">{{ regionLabel(f.region) }}</dd></div>
      <div><dt class="lbl">Connection</dt><dd>{{ f.connection }}</dd></div>
      <div><dt class="lbl">First seen</dt><dd class="mono">{{ f.first_seen }}</dd></div>
      <div><dt class="lbl">Last seen</dt><dd class="mono">{{ f.last_seen }}</dd></div>
      <div v-if="f.resolved_on"><dt class="lbl">Resolved on</dt><dd class="mono">{{ f.resolved_on }}</dd></div>
      <div class="wide">
        <dt class="lbl">Resource</dt>
        <dd>
          <span v-if="f.resource_name" class="res-name">{{ f.resource_name }}</span>
          <span class="mono path">{{ f.resource_uid }}</span>
          <CopyButton :value="f.resource_uid" label="Copy uid" />
          <RouterLink v-if="f.resource_id != null" class="btn btn-ghost btn-sm" :to="{ name: 'resources', query: { open: String(f.resource_id) } }">Open resource</RouterLink>
          <span v-else class="cap">Not in inventory</span>
        </dd>
      </div>
    </dl>

    <AlertBanner v-if="fetched.error.value" kind="fail">
      The tool's explanation didn't load: {{ fetched.error.value }}
      <template #action><button type="button" class="btn btn-secondary btn-sm" @click="fetched.reload">Retry</button></template>
    </AlertBanner>
    <div v-else-if="!detail" class="skeleton sk-48" aria-busy="true"></div>
    <template v-else>
      <section v-if="detail.risk" class="block" aria-label="Risk">
        <span class="lbl">Risk</span>
        <ToolText :text="detail.risk" />
      </section>
      <section v-if="detail.description" class="block" aria-label="What the check evaluates">
        <span class="lbl">What the check evaluates</span>
        <ToolText :text="detail.description" />
      </section>
    </template>

    <section class="block remediation" aria-label="Remediation">
      <span class="lbl">Remediation</span>
      <ToolText v-if="f.remediation_text" :text="f.remediation_text" />
      <p v-else class="cap">No remediation text from the tool.</p>
      <template v-if="detail">
        <div v-for="c in code" :key="c.key" class="snippet">
          <div class="snippet-head">
            <span class="lbl">{{ c.label }}</span>
            <CopyButton :value="c.body" :label="`Copy the ${c.label} remediation`" />
          </div>
          <pre class="code" tabindex="0" :aria-label="`${c.label} remediation`">{{ c.body }}</pre>
        </div>
        <div v-if="consoleSteps" class="snippet">
          <span class="lbl">In the AWS console</span>
          <ToolText :text="consoleSteps" />
        </div>
        <p v-if="code.length" class="cap">Review and adapt before applying: placeholders such as &lt;BUCKET_NAME&gt; are the tool's. Argus never applies a fix.</p>
      </template>
      <ul v-if="guide || links.length" class="links">
        <li v-if="guide"><a :href="guide" target="_blank" rel="noopener noreferrer">Remediation guide ↗</a></li>
        <li v-for="l in links" :key="l">
          <a :href="l" target="_blank" rel="noopener noreferrer" class="mono">{{ l }} ↗</a>
        </li>
      </ul>
      <p v-if="detail?.notes" class="cap">{{ detail.notes }}</p>
    </section>

    <CommandsBlock v-if="detail?.commands?.length" :commands="detail.commands" />
  </div>
</template>

<style scoped>
.detail-body {
  position: sticky;
  left: 0;
  width: 100cqi;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: var(--s-12);
  padding: var(--s-12) var(--s-16) var(--s-16);
}

.full-title {
  margin: 0;
  overflow-wrap: anywhere;
}

.own-link {
  align-self: flex-start;
}

.block {
  display: flex;
  flex-direction: column;
  gap: var(--s-6);
  font-size: 14px;
  min-width: 0;
}

.said {
  margin: 0;
  max-width: 80ch;
  overflow-wrap: anywhere;
}

.reason {
  color: var(--text-2);
  font-size: 13px;
}

.evidence-link {
  align-self: flex-start;
}

.facts {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--s-10) var(--s-20);
  font-size: 13px;
}

/* A long check id or resource has no break points (underscores): it wraps inside its own
   cell instead of running into the next one. */
.facts > div {
  min-width: 0;
}

.facts dd {
  margin: 2px 0 0;
  overflow-wrap: anywhere;
}

.facts .wide {
  grid-column: 1 / -1;
}

.facts .wide dd {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--s-8);
}

.cats {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-4);
}

.path {
  overflow-wrap: anywhere;
}

.res-name {
  font-weight: 600;
}

.snippet {
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
  min-width: 0;
}

.snippet-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-8);
}

.snippet .code {
  white-space: pre;
}

.links {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: var(--s-4);
}

.links a {
  color: var(--link);
  overflow-wrap: anywhere;
}

.links a:hover {
  color: var(--link-hover);
}

.links .mono {
  font-size: 12px;
}

.block .cap {
  margin: 0;
}

@media (max-width: 600px) {
  .detail-body {
    position: static;
    width: auto;
    padding: var(--s-4) 0 var(--s-8);
  }
}
</style>
