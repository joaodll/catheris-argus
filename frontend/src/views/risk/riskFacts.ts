/**
 * A Risk row's facts line (ADR-0049, spec frontend/4180ca5e): what made its combinations, in
 * words, each fact leading to where it comes from. A list fact opens that list filtered to the
 * resource with the filters Risk counts with (open, not muted or suppressed), so the list shows
 * the same findings. A door, an admin fact or a credential opens the resource's own panel, where
 * its connections show them.
 */
import type { RouteLocationRaw } from 'vue-router'
import type { Schemas } from '@/api/client'
import { emptyFilters, filtersToQuery } from '@/views/investigate/findingFilters'
import { emptyVulnerabilityFilters, vulnerabilityFiltersToQuery } from '@/views/investigate/vulnerabilityFilters'

export interface Fact {
  key: string
  text: string
  // A list to open; `panel`: the resource's panel (its internet door when `door`).
  to?: RouteLocationRaw
  panel?: 'door' | 'resource'
}

// CloudFox's check for a secret in a function's environment (cloudfox/parse.py).
const SECRET_CHECK = 'cloudfox_env_var_secret'
const HIGH = ['critical', 'high'] as const
const CREDENTIAL: Record<string, string> = {
  access_key: 'an active access key',
  console_password_no_mfa: 'a console password without MFA',
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

function vulnerabilities(resource: number, extra: { exploitable?: boolean; severity?: typeof HIGH }): RouteLocationRaw {
  const filters = { ...emptyVulnerabilityFilters(), resource, muted: 'hide' as const }
  if (extra.exploitable) filters.exploitable = true
  if (extra.severity) filters.severity = [...extra.severity]
  return { name: 'vulnerabilities', query: { ...vulnerabilityFiltersToQuery(filters), tab: 'list' } }
}

function misconfigurations(resource: number, extra: { severity?: typeof HIGH; check?: string }): RouteLocationRaw {
  const filters = { ...emptyFilters(), resource, muted: 'hide' as const, result: ['FAIL' as const] }
  if (extra.severity) filters.severity = [...extra.severity]
  if (extra.check) filters.check = [extra.check]
  return { name: 'misconfigurations', query: { ...filtersToQuery(filters), tab: 'list' } }
}

/** EPSS as a whole percentage; under 1% says so rather than 0%. */
function epss(score: number): string {
  const pct = Math.round(score * 100)
  return pct < 1 ? '<1%' : `${pct}%`
}

export function riskFacts(row: Schemas['RiskRow']): Fact[] {
  const id = row.resource_id
  const facts: Fact[] = []
  if (row.door) {
    facts.push({ key: 'door', text: "Open to the internet (Argus's rules)", panel: 'door' })
  }
  if (row.exploitable_cves > 0) {
    facts.push({
      key: 'exploitable',
      text: `${plural(row.exploitable_cves, 'CVE')} with a public exploit`,
      to: vulnerabilities(id, { exploitable: true }),
    })
  }
  if (row.high_cves > 0) {
    facts.push({ key: 'high-cves', text: `${plural(row.high_cves, 'critical or high CVE')}`, to: vulnerabilities(id, { severity: HIGH }) })
  }
  if (row.max_epss != null && (row.exploitable_cves > 0 || row.high_cves > 0)) {
    facts.push({ key: 'epss', text: `EPSS ${epss(row.max_epss)}` })
  }
  if (row.high_misconfigurations > 0) {
    facts.push({
      key: 'misconfigurations',
      text: `${plural(row.high_misconfigurations, 'critical or high misconfiguration')}`,
      to: misconfigurations(id, { severity: HIGH }),
    })
  }
  if (row.env_secret) {
    facts.push({ key: 'secret', text: 'Secret in its environment variables (CloudFox)', to: misconfigurations(id, { check: SECRET_CHECK }) })
  }
  if (row.admin) {
    facts.push({ key: 'admin', text: 'Admin, or can make itself admin', panel: 'resource' })
  }
  if (row.credential_kinds.length) {
    const kinds = row.credential_kinds.map((k) => CREDENTIAL[k] ?? k).join(' and ')
    facts.push({ key: 'credentials', text: `Signs in from anywhere: ${kinds}`, panel: 'resource' })
  }
  return facts
}
