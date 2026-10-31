/**
 * The Misconfigurations filters and the URL (docs/ui/screens.md, E7): every filter lives in the query
 * string, repeated for several values, defaults left out, so a filtered list can be bookmarked,
 * shared and restored by Back. A value the page does not know is ignored, never sent.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { PROVIDERS, type Provider } from '@/providers'
import { SEVERITIES, type Severity } from '@/views/overview/severity'
import type { FindingState } from './labels'
import { FINDING_REACHES, type FindingReach } from './reachReason'

export type Tool = 'prowler' | 'cloudfox'
export type Result = 'FAIL' | 'MANUAL'
export type Muted = 'any' | 'hide' | 'only'
export type Order = 'severity' | 'severity_asc' | 'last_seen_desc' | 'last_seen_asc'

export interface FindingFilters {
  severity: Severity[]
  connection: number[]
  provider: Provider[]
  tool: Tool[]
  category: string[]
  service: string[]
  type: string[]
  check: string[]
  // What Argus's internet rules say (ADR-0035, sixth amendment).
  reach: FindingReach[]
  region: string[]
  result: Result[]
  muted: Muted
  new: boolean
  state: FindingState
  q: string
  resource: number | null
}

/** The filters in row 2 (More filters): how many are set, for the button's count. */
export const SECONDARY: (keyof FindingFilters)[] = ['service', 'type', 'check', 'reach', 'region', 'result', 'muted', 'new']

const TOOLS: Tool[] = ['prowler', 'cloudfox']
const PROVIDER_IDS: Provider[] = PROVIDERS.map((p) => p.id)
const RESULTS: Result[] = ['FAIL', 'MANUAL']
const MUTED: Muted[] = ['any', 'hide', 'only']
const STATES: FindingState[] = ['open', 'reopened', 'resolved', 'accepted_risk']
const ORDERS: Order[] = ['severity', 'severity_asc', 'last_seen_desc', 'last_seen_asc']
const LIST_MAX = 50 // as the API: at most 50 values per filter

function strings(value: LocationQuery[string] | undefined): string[] {
  const all = Array.isArray(value) ? value : value == null ? [] : [value]
  return [...new Set(all.filter((v): v is string => typeof v === 'string' && v !== ''))].slice(0, LIST_MAX)
}

function oneOf<T extends string>(value: LocationQuery[string] | undefined, allowed: readonly T[], fallback: T): T {
  const first = strings(value)[0]
  return allowed.includes(first as T) ? (first as T) : fallback
}

function known<T extends string>(value: LocationQuery[string] | undefined, allowed: readonly T[]): T[] {
  return strings(value).filter((v): v is T => allowed.includes(v as T))
}

function ids(value: LocationQuery[string] | undefined): number[] {
  return strings(value)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n > 0)
}

export function parseFilters(query: LocationQuery): FindingFilters {
  const resource = ids(query.resource)[0] ?? null
  return {
    severity: known(query.severity, SEVERITIES),
    connection: ids(query.connection),
    provider: known(query.provider, PROVIDER_IDS),
    tool: known(query.tool, TOOLS),
    category: strings(query.category),
    service: strings(query.service),
    type: strings(query.type),
    check: strings(query.check),
    reach: known(query.reach, FINDING_REACHES),
    region: strings(query.region),
    result: known(query.result, RESULTS),
    muted: oneOf(query.muted, MUTED, 'any'),
    new: query.new === '1',
    state: oneOf(query.state, STATES, 'open'),
    q: strings(query.q)[0]?.slice(0, 200) ?? '',
    resource,
  }
}

export function parseOrder(query: LocationQuery): Order {
  return oneOf(query.order, ORDERS, 'severity')
}

/** ?finding=<id>: one finding's own link (it opens alone, expanded, whatever its state). */
export function parseFinding(query: LocationQuery): number | null {
  return ids(query.finding)[0] ?? null
}

export function parsePage(query: LocationQuery): number {
  const page = Number(strings(query.page)[0])
  return Number.isInteger(page) && page > 1 ? page : 1
}

/** The query string for these filters: defaults left out. */
export function filtersToQuery(f: FindingFilters): LocationQueryRaw {
  const list = <T>(values: T[]): string[] | undefined => (values.length ? values.map(String) : undefined)
  return {
    severity: list(f.severity),
    connection: list(f.connection),
    provider: list(f.provider),
    tool: list(f.tool),
    category: list(f.category),
    service: list(f.service),
    type: list(f.type),
    check: list(f.check),
    reach: list(f.reach),
    region: list(f.region),
    result: list(f.result),
    muted: f.muted === 'any' ? undefined : f.muted,
    new: f.new ? '1' : undefined,
    state: f.state === 'open' ? undefined : f.state,
    q: f.q || undefined,
    resource: f.resource == null ? undefined : String(f.resource),
  }
}

/** The list request's filter parameters (GET /findings). */
export function apiFilters(f: FindingFilters) {
  return {
    severity: f.severity,
    connection_id: f.connection,
    provider: f.provider,
    tool: f.tool,
    category: f.category,
    service: f.service,
    resource_type: f.type,
    check_id: f.check,
    reach: f.reach,
    region: f.region,
    status: f.result,
    muted: f.muted,
    new: f.new,
    state: f.state,
    q: f.q || null,
    resource_id: f.resource,
  }
}

export function emptyFilters(): FindingFilters {
  return parseFilters({})
}

/** True when any filter differs from its default (Clear filters is shown). */
export function isFiltered(f: FindingFilters): boolean {
  return JSON.stringify(filtersToQuery(f)) !== JSON.stringify(filtersToQuery(emptyFilters()))
}

/** How many row-2 filters are set. */
export function secondaryCount(f: FindingFilters): number {
  return SECONDARY.filter((key) => {
    const value = f[key]
    return Array.isArray(value) ? value.length > 0 : key === 'muted' ? value !== 'any' : Boolean(value)
  }).length
}

/** A Prowler category slug in words: "internet-exposed" -> "Internet exposed". */
export function categoryLabel(slug: string): string {
  const words = slug.replace(/[-_]+/g, ' ').trim()
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : slug
}

/** ?view=checks: the list by check (2026-10-31). The list is the default and is left out. */
export type View = 'list' | 'checks'
const VIEWS: View[] = ['list', 'checks']

export function parseView(query: LocationQuery): View {
  return oneOf(query.view, VIEWS, 'list')
}

export function viewToQuery(view: View): string | undefined {
  return view === 'checks' ? 'checks' : undefined
}

/** A check's group opens the list filtered to it: its check id and its tool, the other filters
 * kept. */
export function groupFilters(f: FindingFilters, group: { tool: string; check_id: string }): FindingFilters {
  const tool = TOOLS.find((t) => t === group.tool)
  return { ...f, check: [group.check_id], tool: tool ? [tool] : f.tool }
}

/** The chosen checks the facets keep: those they offer. */
export function keptChecks(f: FindingFilters, offered: string[]): string[] {
  return f.check.filter((c) => offered.includes(c))
}

/** Query-string readers the Vulnerabilities filters share. */
export { ids, known, oneOf, strings }
