/**
 * The Security Map's facts on a card (ADR-0051, card B; spec in the palace, frontend/4242ef35):
 * open misconfigurations with the worst severity, open vulnerabilities and a public exploit, and
 * reachable from the internet as Argus's rules confirm it. The API counts them as the Resources
 * list does (GET /map/security/graph), so each link here opens a list with the same count. A
 * missing fact is "not covered", never a zero. The Resource Map has none of this.
 */
import type { RouteLocationRaw } from 'vue-router'
import type { Schemas } from '@/api/client'
import { SEVERITY_LABEL, SEVERITIES, type Severity } from '@/views/overview/severity'

export type NodeFacts = Schemas['NodeFacts']

// The lines that are security judgements (relationships.SECURITY_EDGE_TYPES in the API): drawn
// on the Security Map only, heavier than a connection.
export const SECURITY_EDGE_TYPES: ReadonlySet<string> = new Set([
  'IS_ADMIN',
  'CAN_PRIVESC_TO',
  'CAN_ESCALATE_TO',
  'OUTSIDER',
  'HAS_CREDENTIAL',
  'INTERNET_REACHABLE',
])

/** The node's facts, when the response carried them (only the Security Map's does). */
export function factsOf(node: { facts?: NodeFacts | null } | null | undefined): NodeFacts | null {
  return node?.facts ?? null
}

export function worstOf(facts: NodeFacts | null): Severity | null {
  const worst = facts?.misconfigurations?.worst
  return worst && (SEVERITIES as readonly string[]).includes(worst) ? (worst as Severity) : null
}

/** The pill's count: null when there is none to show (none open, or not covered). */
export function pillCount(facts: NodeFacts | null): string | null {
  const n = facts?.misconfigurations?.open ?? 0
  if (n <= 0) return null
  return n > 999 ? '999+' : String(n)
}

/** The CSS token suffix of a severity: --sev-<suffix> and --sev-<suffix>-text. */
export function sevToken(severity: Severity): string {
  return severity === 'informational' ? 'info' : severity
}

export interface Marks {
  internet: boolean
  vulnerable: boolean
  exploit: boolean
}

export function marksOf(facts: NodeFacts | null): Marks {
  const v = facts?.vulnerabilities
  return { internet: !!facts?.internet_reachable, vulnerable: (v?.open ?? 0) > 0, exploit: (v?.exploitable ?? 0) > 0 }
}

const many = (n: number, one: string, more: string): string => `${n.toLocaleString('en-US')} ${n === 1 ? one : more}`

/** Each fact in words: the tooltip, the panel and the keyboard announcement. Nothing for a type
 * no scanner covers. */
export function factLines(facts: NodeFacts | null, connection: string): string[] {
  if (!facts) return []
  const out: string[] = []
  const m = facts.misconfigurations
  if (m == null) out.push(`Misconfigurations: not covered (Prowler and CloudFox have not scanned ${connection})`)
  else if (m.open === 0) out.push('No open misconfigurations')
  else out.push(`${many(m.open, 'open misconfiguration', 'open misconfigurations')}, worst ${SEVERITY_LABEL[worstOf(facts) ?? 'informational']}`)
  const v = facts.vulnerabilities
  if (v != null) {
    if (!v.scanned && v.open === 0) out.push('Not scanned for vulnerabilities')
    else if (v.open === 0) out.push('No open vulnerabilities')
    else out.push(`${many(v.open, 'open vulnerability', 'open vulnerabilities')}${v.exploitable ? `, ${v.exploitable.toLocaleString('en-US')} with a public exploit` : ''}`)
  }
  if (facts.internet_reachable) out.push("Reachable from the internet: Argus's rules confirm it")
  return out
}

/** The List view's words after the type: what is there, or "Not covered"; empty for nothing. */
export function factSub(facts: NodeFacts | null): string[] {
  if (!facts) return []
  const out: string[] = []
  const m = facts.misconfigurations
  if (m == null) out.push('Misconfigurations not covered')
  else if (m.open > 0) out.push(`${many(m.open, 'misconfiguration', 'misconfigurations')} (${SEVERITY_LABEL[worstOf(facts) ?? 'informational']})`)
  const v = facts.vulnerabilities
  if (v && v.open > 0) out.push(many(v.open, 'vulnerability', 'vulnerabilities'))
  if (v && v.exploitable > 0) out.push('Exploit')
  if (facts.internet_reachable) out.push('Internet reachable')
  return out
}

/** Where each fact's link goes: the list filtered to the resource, counting what the card counts
 * (open, FAIL, not muted, both tools; open CVEs not suppressed; a confirmed reach). */
export function factLinks(resourceId: number): { misconfigurations: RouteLocationRaw; vulnerabilities: RouteLocationRaw; internet: RouteLocationRaw } {
  const resource = String(resourceId)
  return {
    misconfigurations: { name: 'misconfigurations', query: { resource, result: 'FAIL', muted: 'hide' } },
    vulnerabilities: { name: 'vulnerabilities', query: { resource, muted: 'hide' } },
    internet: { name: 'misconfigurations', query: { resource, result: 'FAIL', muted: 'hide', reach: 'confirmed' } },
  }
}
