/**
 * Posture -> Compliance (docs/ui/screens.md E9, E10): the URL state of both pages and the way a
 * score and its change read. Defaults are left out of the URL; a value the page does not know
 * is ignored. A missing score is "Not assessed", never 0.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { parseRange, type Range } from '@/components/charts/chart'
import { decimal, signed } from '@/format'
import { PROVIDERS, type Provider } from '@/providers'

export type ListOrder = 'score_asc' | 'score_desc' | 'name_asc' | 'name_desc'
export type Status = 'FAIL' | 'MANUAL' | 'PASS'

export interface ListQuery {
  q: string
  provider: Provider[] // the framework's own provider; empty = every provider
  connection: number // 0 = all connections
  order: ListOrder
  page: number
}

export interface FrameworkQuery {
  connection: number
  range: Range
  status: Status | null
  q: string
  page: number // requirements
  apage: number // accounts
}

const ORDERS: ListOrder[] = ['score_asc', 'score_desc', 'name_asc', 'name_desc']
const STATUSES: Status[] = ['FAIL', 'MANUAL', 'PASS']
const PROVIDER_IDS: Provider[] = PROVIDERS.map((p) => p.id)

function first(value: LocationQuery[string] | undefined): string {
  const v = Array.isArray(value) ? value[0] : value
  return typeof v === 'string' ? v : ''
}

function positive(value: LocationQuery[string] | undefined, fallback: number): number {
  const n = Number(first(value))
  return Number.isInteger(n) && n > 0 ? n : fallback
}

/** Every known provider in the query, once, in display order. */
function providers(value: LocationQuery[string] | undefined): Provider[] {
  const all = Array.isArray(value) ? value : [value]
  return PROVIDER_IDS.filter((p) => all.includes(p))
}

export function parseList(query: LocationQuery): ListQuery {
  const order = first(query.order)
  return {
    q: first(query.q).slice(0, 200),
    provider: providers(query.provider),
    connection: positive(query.connection, 0),
    order: ORDERS.includes(order as ListOrder) ? (order as ListOrder) : 'score_asc',
    page: positive(query.page, 1),
  }
}

export function listToQuery(state: ListQuery): LocationQueryRaw {
  return {
    q: state.q || undefined,
    provider: state.provider.length ? [...state.provider] : undefined,
    connection: state.connection ? String(state.connection) : undefined,
    order: state.order === 'score_asc' ? undefined : state.order,
    page: state.page > 1 ? String(state.page) : undefined,
  }
}

export function parseFramework(query: LocationQuery): FrameworkQuery {
  const status = first(query.status)
  return {
    connection: positive(query.connection, 0),
    range: parseRange(first(query.range)),
    status: STATUSES.includes(status as Status) ? (status as Status) : null,
    q: first(query.q).slice(0, 200),
    page: positive(query.page, 1),
    apage: positive(query.apage, 1),
  }
}

export function frameworkToQuery(state: FrameworkQuery): LocationQueryRaw {
  return {
    connection: state.connection ? String(state.connection) : undefined,
    range: state.range === '6M' ? undefined : state.range,
    status: state.status ?? undefined,
    q: state.q || undefined,
    page: state.page > 1 ? String(state.page) : undefined,
    apage: state.apage > 1 ? String(state.apage) : undefined,
  }
}

/** "71.4 %", or "Not assessed". */
export function scoreText(score: number | null | undefined): string {
  return score == null ? 'Not assessed' : `${decimal(score)} %`
}

/** A score change: a higher score is better. "▲ +7.2", "▼ −3", "±0", or "—" when unknown. */
export function scoreChange(value: number | null | undefined): { text: string; color: string; label: string } {
  if (value == null) return { text: '—', color: 'var(--text-3)', label: 'No change to show' }
  const rounded = Math.round(value * 10) / 10
  if (rounded === 0) return { text: '±0', color: 'var(--delta-flat)', label: 'No change' }
  return rounded > 0
    ? { text: `▲ ${signed(rounded, 1)}`, color: 'var(--delta-better)', label: `Up ${decimal(rounded)} points` }
    : { text: `▼ ${signed(rounded, 1)}`, color: 'var(--delta-worse)', label: `Down ${decimal(-rounded)} points` }
}

/** The name to show for a framework: Prowler's, or its key until Argus has one. */
export function frameworkName(f: { name?: string | null; framework: string }): string {
  return f.name || f.framework
}

/** A short name where space is tight (the Overview strip's select): Prowler's family and
 * version, "CIS 6.0", "NIST 800 53 Revision 5"; the full name when there is no family. */
export function frameworkShortName(f: { name?: string | null; framework: string; family?: string | null; version?: string | null }): string {
  if (!f.family) return frameworkName(f)
  return [f.family.replaceAll('-', ' '), f.version].filter(Boolean).join(' ')
}
