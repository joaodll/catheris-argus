/**
 * The Resources filters and the URL (2026-11-06), as the Misconfigurations and Vulnerabilities
 * filters do it: every filter in the query string, repeated for several values, defaults left
 * out, so the Resources summary's numbers link to the list that reproduces them, and a filtered
 * list can be bookmarked, shared and restored by Back. A value the page does not know is
 * ignored, never sent. The open resource sheet (?open=) and the page are read apart.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { day, ids, oneOf, strings } from './findingFilters'

// Open CVEs (ADR-0042): any, critical or high, or with a public exploit.
export type VulnerabilityLevel = 'any' | 'high' | 'exploitable'
// Open misconfigurations (open, FAIL, not muted): any, or critical or high.
export type MisconfigurationLevel = 'any' | 'high'
export type ResourceOrder = 'name_asc' | 'name_desc' | 'last_seen_desc' | 'last_seen_asc'

export interface ResourceFilters {
  connection: number[]
  type: string[]
  region: string[]
  q: string
  vulnerabilities: VulnerabilityLevel | null
  misconfigurations: MisconfigurationLevel | null
  // An open misconfiguration that Argus's rules confirm is reachable from the internet.
  internet: boolean
  // Only the types the Overview counts as assets.
  assets: boolean
  includeDeleted: boolean
  // First seen, or removed, on or after / on or before (YYYY-MM-DD, '' for no bound). A removed
  // bound lists removed resources only.
  firstSeenFrom: string
  firstSeenTo: string
  removedFrom: string
  removedTo: string
}

/** The filters in row 2 (More filters): how many are set, for the button's count. */
export const SECONDARY: (keyof ResourceFilters)[] = ['misconfigurations', 'internet', 'assets', 'firstSeenFrom', 'removedFrom', 'includeDeleted']

const TYPE_MAX = 200 // as the API: a summary's service links with every type of the service
const VULNERABILITY_LEVELS: VulnerabilityLevel[] = ['any', 'high', 'exploitable']
const MISCONFIGURATION_LEVELS: MisconfigurationLevel[] = ['any', 'high']
const ORDERS: ResourceOrder[] = ['name_asc', 'name_desc', 'last_seen_desc', 'last_seen_asc']

function level<T extends string>(value: LocationQuery[string] | undefined, allowed: readonly T[]): T | null {
  const first = strings(value)[0]
  return allowed.includes(first as T) ? (first as T) : null
}

export function parseResourceFilters(query: LocationQuery): ResourceFilters {
  return {
    connection: ids(query.connection),
    type: strings(query.type, TYPE_MAX),
    region: strings(query.region),
    q: strings(query.q)[0]?.slice(0, 200) ?? '',
    vulnerabilities: level(query.vulnerabilities, VULNERABILITY_LEVELS),
    misconfigurations: level(query.misconfigurations, MISCONFIGURATION_LEVELS),
    internet: query.internet === '1',
    assets: query.assets === '1',
    includeDeleted: query.deleted === '1',
    firstSeenFrom: day(query.first_seen_from),
    firstSeenTo: day(query.first_seen_to),
    removedFrom: day(query.removed_from),
    removedTo: day(query.removed_to),
  }
}

export function parseResourceOrder(query: LocationQuery): ResourceOrder {
  return oneOf(query.order, ORDERS, 'name_asc')
}

/** The query string for these filters: defaults left out. */
export function resourceFiltersToQuery(f: ResourceFilters): LocationQueryRaw {
  const list = <T>(values: T[]): string[] | undefined => (values.length ? values.map(String) : undefined)
  return {
    connection: list(f.connection),
    type: list(f.type),
    region: list(f.region),
    q: f.q || undefined,
    vulnerabilities: f.vulnerabilities ?? undefined,
    misconfigurations: f.misconfigurations ?? undefined,
    internet: f.internet ? '1' : undefined,
    assets: f.assets ? '1' : undefined,
    deleted: f.includeDeleted ? '1' : undefined,
    first_seen_from: f.firstSeenFrom || undefined,
    first_seen_to: f.firstSeenTo || undefined,
    removed_from: f.removedFrom || undefined,
    removed_to: f.removedTo || undefined,
  }
}

/** The list request's filter parameters (GET /resources). */
export function resourceApiFilters(f: ResourceFilters) {
  return {
    connection_id: f.connection,
    type: f.type,
    region: f.region,
    q: f.q || null,
    vulnerabilities: f.vulnerabilities,
    misconfigurations: f.misconfigurations,
    internet: f.internet,
    assets: f.assets,
    include_deleted: f.includeDeleted,
    first_seen_from: f.firstSeenFrom || null,
    first_seen_to: f.firstSeenTo || null,
    deleted_from: f.removedFrom || null,
    deleted_to: f.removedTo || null,
  }
}

export function emptyResourceFilters(): ResourceFilters {
  return parseResourceFilters({})
}

/** True when any filter differs from its default (Clear filters is shown). */
export function isResourceFiltered(f: ResourceFilters): boolean {
  return Object.values(resourceFiltersToQuery(f)).some((v) => v !== undefined)
}

/** How many row-2 filters are set. */
export function resourceSecondaryCount(f: ResourceFilters): number {
  return SECONDARY.filter((key) => {
    if (key === 'firstSeenFrom') return Boolean(f.firstSeenFrom || f.firstSeenTo) // one filter, two ends
    if (key === 'removedFrom') return Boolean(f.removedFrom || f.removedTo)
    return Boolean(f[key])
  }).length
}

/** A link to the Resources list with these filters (the summary's numbers, the Overview's). */
export function resourcesLink(filters: Partial<ResourceFilters>): { name: 'resources'; query: LocationQueryRaw } {
  return { name: 'resources', query: { ...resourceFiltersToQuery({ ...emptyResourceFilters(), ...filters }), tab: 'list' } }
}
