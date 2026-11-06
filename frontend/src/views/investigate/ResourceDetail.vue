<script setup lang="ts">
/**
 * One resource, read-only, a block per tool (docs/ui/screens.md, E11, Resource panel): what
 * Steampipe describes, what Prowler checks, what CloudFox shows an attacker could use, then its
 * connections, tags and configuration. The Resources sheet (E8) shows this body.
 */
import { computed, ref, watch } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { api, unwrap, type Schemas } from '@/api/client'
import AlertBanner from '@/components/AlertBanner.vue'
import CopyButton from '@/components/CopyButton.vue'
import CommandsBlock from './CommandsBlock.vue'
import SeverityTag from '@/components/SeverityTag.vue'
import ToolChip from '@/components/ToolChip.vue'
import { useResource } from '@/composables/useResource'
import EdgeList from './EdgeList.vue'
import { findingLine, regionLabel } from './labels'
import DoorEvidence from './DoorEvidence.vue'
import { doorOfEdge, doorWhy } from './doorWhy'
import ReachBadge from './ReachBadge.vue'
import ExploitMark from './ExploitMark.vue'
import { coverageReason, epssPercent, lastScanned, packageLine } from './vulnerability'
import { SEVERITIES } from '@/views/overview/severity'
import { utc } from '@/format'
import { scannerName } from '@/tools'

const props = defineProps<{
  resourceId: number
  connectionName: (id: number) => string
  // Where a connected resource opens.
  resourceLink: (id: number) => RouteLocationRaw
  // A block to bring into view once it shows: a finding's See the evidence opens the sheet at
  // From the internet (ADR-0035, sixth amendment).
  at?: 'from-internet' | null
}>()
const emit = defineEmits<{ loaded: [resource: Schemas['ResourceDetail'] | null] }>()

const SHOWN = 5
type Tool = 'prowler' | 'cloudfox'

const detail = useResource(
  () =>
    unwrap(
      api.GET('/api/v1/resources/{resource_id}', {
        params: { path: { resource_id: props.resourceId } },
      }),
    ),
  { watch: [() => props.resourceId] },
)
// The resource's open misconfigurations, as the Resources list's column counts them (one
// definition, 2026-11-06): open or reopened, status FAIL, not muted.
const OPEN_MISCONFIGURATIONS = { status: ['FAIL' as const], muted: 'hide' as const }
const toolFindings = (tool: Tool) =>
  useResource(
    () =>
      unwrap(
        api.GET('/api/v1/findings', { params: { query: { resource_id: props.resourceId, tool: [tool], ...OPEN_MISCONFIGURATIONS, limit: SHOWN } } }),
      ),
    { watch: [() => props.resourceId] },
  )
const findings: Record<Tool, ReturnType<typeof toolFindings>> = { prowler: toolFindings('prowler'), cloudfox: toolFindings('cloudfox') }

// Until the detail arrives (or while another resource loads), nothing of the old one shows.
const current = computed(() => (detail.data.value?.id === props.resourceId ? detail.data.value : null))
watch(current, (r) => emit('loaded', r), { immediate: true })

const connection = computed(() => (current.value ? props.connectionName(current.value.connection_id) : ''))
const cloudfoxEdges = computed(() => (current.value?.edges ?? []).filter((e) => e.origin === 'cloudfox'))
// The internet rules' verdict on this resource, when it faces the internet (ADR-0035): a badge,
// a why-line and the evidence.
const door = computed(() => {
  for (const e of current.value?.edges ?? []) {
    const d = e.source_uid === 'internet' ? doorOfEdge(e) : null
    if (d) return { ...d, why: doorWhy(d) }
  }
  return null
})
const doorBlock = ref<HTMLElement | null>(null)
watch([doorBlock, () => props.at], ([block, at]) => {
  if (block && at === 'from-internet') block.scrollIntoView({ block: 'start' })
})
const tags = computed(() => Object.entries(current.value?.tags ?? {}))
const configText = computed(() => (current.value?.config ? JSON.stringify(current.value.config, null, 2) : null))

const TOOLS: { tool: Tool; name: string }[] = [
  { tool: 'prowler', name: 'Prowler' },
  { tool: 'cloudfox', name: 'CloudFox' },
]

// The provider's vulnerability scanner's view of this resource (ADR-0042, AWS Inspector on AWS);
// null for a provider and type no scanner covers.
const vulns = computed(() => {
  const section = current.value?.vulnerabilities
  if (!section || !current.value) return null
  const open = Object.values(section.by_severity).reduce((sum, n) => sum + n, 0)
  const inactive = section.coverage.find((c) => !c.active)
  const scanner = scannerName(section.scanner)
  return {
    ...section,
    open,
    scanner,
    collected: current.value.scanned.vulnerabilities != null,
    scanned: section.coverage.some((c) => c.active),
    lastScanned: lastScanned(section.coverage),
    reason: coverageReason(section.scanner, inactive?.status_reason) ?? `${scanner} reports no coverage for it.`,
    counts: SEVERITIES.flatMap((s) => (section.by_severity[s] ? [{ severity: s, count: section.by_severity[s]! }] : [])),
  }
})
</script>

<template>
  <AlertBanner v-if="detail.error.value" kind="fail">
    This resource didn't load: {{ detail.error.value }}
    <template #action><button type="button" class="btn btn-secondary btn-sm" @click="detail.reload">Retry</button></template>
  </AlertBanner>
  <div v-else-if="!current" aria-busy="true" class="loading">
    <div v-for="n in 4" :key="n" class="skeleton sk-48"></div>
  </div>
  <div v-else class="detail">
    <section class="block" aria-labelledby="rd-steampipe">
      <h3 id="rd-steampipe" class="lbl tool-title">Steampipe <ToolChip tool="steampipe" /></h3>
      <dl class="facts">
        <div class="wide">
          <dt class="lbl">Resource UID</dt>
          <dd class="uid"><span class="mono path">{{ current.resource_uid }}</span><CopyButton :value="current.resource_uid" label="Copy uid" /></dd>
        </div>
        <div><dt class="lbl">Native id</dt><dd class="mono path">{{ current.native_id }}</dd></div>
        <div><dt class="lbl">Connection</dt><dd>{{ connection }}</dd></div>
        <div><dt class="lbl">Region</dt><dd class="mono">{{ regionLabel(current.region) }}</dd></div>
        <div><dt class="lbl">VPC</dt><dd class="mono">{{ current.vpc_id ?? '—' }}</dd></div>
        <div><dt class="lbl">First seen</dt><dd class="mono">{{ current.first_seen }}</dd></div>
        <div><dt class="lbl">Last seen</dt><dd class="mono">{{ current.last_seen }}</dd></div>
        <div v-if="current.deleted_on"><dt class="lbl">Deleted on</dt><dd class="mono">{{ current.deleted_on }}</dd></div>
      </dl>
      <p v-if="current.seen_on" class="cap">Configuration as of <span class="mono">{{ current.seen_on }}</span></p>
      <AlertBanner v-else kind="warn">Not in the inventory on {{ current.as_of }}. Shown as last recorded.</AlertBanner>
    </section>

    <section v-for="t in TOOLS" :key="t.tool" class="block" :aria-labelledby="`rd-${t.tool}`">
      <h3 :id="`rd-${t.tool}`" class="lbl tool-title">{{ t.name }} <ToolChip :tool="t.tool" /></h3>
      <AlertBanner v-if="findings[t.tool].error.value" kind="fail">
        {{ t.name }} findings didn't load: {{ findings[t.tool].error.value }}
        <template #action><button type="button" class="btn btn-secondary btn-sm" @click="findings[t.tool].reload">Retry</button></template>
      </AlertBanner>
      <div v-else-if="!findings[t.tool].data.value" aria-busy="true" class="skeleton sk-48"></div>
      <template v-else-if="findings[t.tool].data.value!.total === 0">
        <template v-if="current.scanned[t.tool]">
          <p class="body">No open {{ t.name }} findings on this resource.</p>
          <p class="cap">Last {{ t.name }} scan of {{ connection }}: <span class="mono">{{ current.scanned[t.tool] }}</span></p>
        </template>
        <p v-else class="body">Not covered: {{ t.name }} has not scanned {{ connection }}.</p>
      </template>
      <template v-else>
        <ul class="rows">
          <li v-for="f in findings[t.tool].data.value!.items" :key="f.id" class="finding-row">
            <SeverityTag :severity="f.severity" />
            <!-- Prowler's result leads, as on Findings (2026-10-31 review). -->
            <RouterLink class="one-line finding-link" :to="{ name: 'misconfigurations', query: { finding: String(f.id) } }" target="_blank" :title="findingLine(f).lead">
              {{ findingLine(f).lead }}<span class="sr-only"> (opens in a new tab)</span>
            </RouterLink>
            <span class="new-tab" aria-hidden="true">↗</span>
            <ReachBadge :reach="f.reach" :reason="f.reach_reason" class="reach" />
          </li>
        </ul>
        <RouterLink
          class="btn btn-ghost btn-sm see-all"
          :to="{ name: 'misconfigurations', query: { resource: String(resourceId), tool: t.tool, result: 'FAIL', muted: 'hide' } }"
        >
          See all {{ findings[t.tool].data.value!.total }} {{ t.name }} findings
        </RouterLink>
      </template>
      <template v-if="t.tool === 'cloudfox' && current.scanned.cloudfox">
        <h4 class="lbl sub">Attacker view</h4>
        <p v-if="cloudfoxEdges.length === 0" class="cap">CloudFox found no connection for this resource.</p>
        <EdgeList v-else :edges="cloudfoxEdges" :resource-id="resourceId" :resource-link="resourceLink" />
      </template>
    </section>

    <section v-if="vulns" class="block" aria-labelledby="rd-vulnerabilities">
      <h3 id="rd-vulnerabilities" class="lbl tool-title">Vulnerabilities <ToolChip tool="vulnerabilities" /></h3>
      <template v-if="!vulns.collected">
        <p class="body">Not covered: vulnerabilities are not collected for {{ connection }}.</p>
        <p class="cap">Add Vulnerabilities to a schedule to collect them from {{ vulns.scanner }}.</p>
      </template>
      <template v-else>
        <template v-if="!vulns.scanned">
          <p class="body">{{ vulns.scanner }} doesn't scan this resource.</p>
          <p class="cap">{{ vulns.reason }}</p>
        </template>
        <template v-else-if="vulns.open === 0">
          <p class="body">No open vulnerabilities on this resource.</p>
          <p class="cap">Last scanned by {{ vulns.scanner }}: <span class="mono">{{ utc(vulns.lastScanned) }}</span></p>
        </template>
        <template v-if="vulns.open > 0">
          <p v-if="!vulns.scanned" class="cap">From an earlier scan:</p>
          <div class="vuln-counts">
            <span v-for="c in vulns.counts" :key="c.severity" class="vuln-count">
              <SeverityTag :severity="c.severity" compact /><span class="mono">{{ c.count }}</span>
            </span>
          </div>
          <p class="cap">
            <template v-if="vulns.lastScanned">Last scanned by {{ vulns.scanner }}: <span class="mono">{{ utc(vulns.lastScanned) }}</span></template>
            <template v-if="vulns.suppressed > 0">{{ vulns.lastScanned ? ' · ' : '' }}{{ vulns.suppressed }} suppressed in {{ vulns.scanner }}</template>
          </p>
          <ul class="rows">
            <li v-for="v in vulns.top" :key="v.finding_id" class="vuln-row">
              <span class="finding-row">
                <SeverityTag :severity="v.severity" />
                <RouterLink
                  class="one-line finding-link"
                  :class="{ mono: v.vulnerability.vulnerability_id }"
                  :to="{ name: 'vulnerabilities', query: { finding: String(v.finding_id) } }"
                  target="_blank"
                  :title="v.title"
                >
                  {{ v.vulnerability.vulnerability_id ?? v.title }}<span class="sr-only"> (opens in a new tab)</span>
                </RouterLink>
                <span class="new-tab" aria-hidden="true">↗</span>
                <span class="vuln-marks">
                  <ExploitMark v-if="v.vulnerability.exploit_available" />
                  <span v-if="epssPercent(v.vulnerability.epss_score)" class="mono step">EPSS {{ epssPercent(v.vulnerability.epss_score) }}</span>
                </span>
              </span>
              <span class="cap mono package">{{ packageLine(v.vulnerability) }}</span>
            </li>
          </ul>
          <RouterLink
            class="btn btn-ghost btn-sm see-all"
            :to="{ name: 'vulnerabilities', query: { resource: String(resourceId) } }"
          >
            See all {{ vulns.open + vulns.suppressed }} vulnerabilit{{ vulns.open + vulns.suppressed === 1 ? 'y' : 'ies' }}
          </RouterLink>
        </template>
      </template>
    </section>

    <section v-if="door" ref="doorBlock" class="block" aria-labelledby="rd-door">
      <h3 id="rd-door" class="lbl">From the internet</h3>
      <div class="door">
        <ReachBadge door :reach="door.reach" />
        <p v-if="door.why" class="cap">{{ door.why }}</p>
      </div>
      <DoorEvidence v-if="door.network.length" :network="door.network" :state="door.state" />
    </section>

    <section class="block" aria-labelledby="rd-edges">
      <h3 id="rd-edges" class="lbl">Connections</h3>
      <p v-if="current.edges.length === 0" class="cap">No connections found for this resource.</p>
      <EdgeList v-else :edges="current.edges" :resource-id="resourceId" :resource-link="resourceLink" />
    </section>

    <section class="block" aria-labelledby="rd-tags">
      <h3 id="rd-tags" class="lbl">Tags</h3>
      <p v-if="tags.length === 0" class="cap">No tags.</p>
      <table v-else class="tags">
        <thead><tr><th scope="col" class="lbl">Key</th><th scope="col" class="lbl">Value</th></tr></thead>
        <tbody>
          <tr v-for="[key, value] in tags" :key="key">
            <td class="mono path">{{ key }}</td>
            <td class="mono path">{{ typeof value === 'string' ? value : JSON.stringify(value) }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <CommandsBlock v-if="current.commands.length" :commands="current.commands" />

    <section class="block" aria-labelledby="rd-config">
      <h3 id="rd-config" class="lbl">Configuration</h3>
      <p v-if="!configText" class="cap">No configuration recorded.</p>
      <template v-else>
        <p class="cap">Secret values are removed when the scan is ingested.</p>
        <details class="config">
          <summary>Show configuration (JSON)</summary>
          <pre class="code json" tabindex="0" aria-label="Configuration (JSON)">{{ configText }}</pre>
        </details>
      </template>
    </section>
  </div>
</template>

<style scoped>
.door {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--s-4);
}

.door .cap {
  margin: 0;
}

.loading,
.detail {
  display: flex;
  flex-direction: column;
}

.loading {
  gap: var(--s-4);
}

.detail {
  gap: var(--s-24);
}

.block {
  display: flex;
  flex-direction: column;
  gap: var(--s-10);
}

.block > .lbl,
.block > .cap,
.block > .body {
  margin: 0;
}

.tool-title {
  display: flex;
  align-items: center;
  gap: var(--s-8);
}

/* The chip names the tool in its own case and face, not the eyebrow's. */
.tool-title :deep(.chip) {
  text-transform: none;
  letter-spacing: normal;
}

.sub {
  margin: var(--s-6) 0 0;
}

.body {
  font-size: 13px;
}

.facts {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: var(--s-10) var(--s-20);
  font-size: 13px;
}

.facts dd {
  margin: 2px 0 0;
}

.facts .wide {
  grid-column: 1 / -1;
}

.uid {
  display: flex;
  align-items: center;
  gap: var(--s-6);
}

.path {
  overflow-wrap: anywhere;
}

.rows {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: var(--s-8);
  font-size: 13px;
}

.finding-row {
  display: flex;
  align-items: center;
  gap: var(--s-10);
  flex-wrap: wrap;
  min-width: 0;
}

.one-line {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Each finding opens alone, in its own tab: the page behind stays as it was. */
.finding-link {
  color: var(--text);
  text-decoration: underline;
  text-decoration-color: var(--border-control);
  text-underline-offset: 3px;
}

.finding-link:hover {
  text-decoration-color: currentcolor;
}

.new-tab {
  color: var(--text-3);
}

.step {
  font-size: 12px;
  color: var(--text-2);
  white-space: nowrap;
}

.see-all {
  align-self: flex-start;
}

.vuln-counts {
  display: flex;
  flex-wrap: wrap;
  gap: var(--s-8);
}

.vuln-count {
  display: inline-flex;
  align-items: center;
  gap: var(--s-6);
}

.vuln-row {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.vuln-marks {
  display: inline-flex;
  align-items: center;
  gap: var(--s-8);
}

.package {
  overflow-wrap: anywhere;
}

.tags {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.tags th {
  text-align: left;
  padding: 0 var(--s-8) var(--s-6) 0;
}

.tags td {
  padding: var(--s-6) var(--s-8) var(--s-6) 0;
  border-top: 1px solid var(--border);
  vertical-align: top;
}

.config summary {
  cursor: pointer;
  font-size: 13px;
  color: var(--link);
}

.json {
  max-height: 480px;
  overflow: auto;
  margin-top: var(--s-10);
  font-size: 12px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
