/**
 * The Attack paths filters and the URL (spec W6 §2.1, §10.9), as on Misconfigurations: every
 * filter in the query string, defaults left out, a value the page does not know ignored.
 * ?route=<id> opens one route in place of the table, ?target=<seq> one of its targets;
 * ?through=<resource id> lists the routes whose listed steps pass a resource; ?crossing=1 with a
 * connection also lists the routes that cross it.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { SEVERITIES, type Severity } from '@/views/overview/severity'
import { ROUTE_CLASSES, type RouteClass } from './routeClass'

export type RouteState = 'open' | 'fixed'
export type RouteOrder = 'severity' | 'last_seen'

export interface RouteFilters {
  severity: Severity[]
  kind: string[]
  // Empty: every class but Latent, which is shown only when asked for (the API's default).
  confidence: RouteClass[]
  connection: number | null
  crossing: boolean
  state: RouteState
  through: number | null
}

const LIST_MAX = 50 // as the API
const KIND = /^[a-z0-9][a-z0-9-]{0,63}$/ // as the API

function strings(value: LocationQuery[string] | undefined): string[] {
  const all = Array.isArray(value) ? value : value == null ? [] : [value]
  return [...new Set(all.filter((v): v is string => typeof v === 'string' && v !== ''))].slice(0, LIST_MAX)
}

function id(value: LocationQuery[string] | undefined): number | null {
  const n = Number(strings(value)[0])
  return Number.isSafeInteger(n) && n > 0 ? n : null
}

export function parseRouteFilters(query: LocationQuery): RouteFilters {
  const connection = id(query.connection)
  const confidence = strings(query.confidence)
  return {
    severity: SEVERITIES.filter((s) => strings(query.severity).includes(s)),
    kind: strings(query.kind).filter((k) => KIND.test(k)),
    confidence: ROUTE_CLASSES.filter((c) => confidence.includes(c)),
    connection,
    crossing: connection != null && strings(query.crossing)[0] === '1',
    state: strings(query.state)[0] === 'fixed' ? 'fixed' : 'open',
    through: id(query.through),
  }
}

export function routeFiltersToQuery(f: RouteFilters): LocationQueryRaw {
  const values = (v: string[]) => (v.length ? v : undefined)
  return {
    severity: values(f.severity),
    kind: values(f.kind),
    confidence: values(f.confidence),
    connection: f.connection == null ? undefined : String(f.connection),
    crossing: f.crossing && f.connection != null ? '1' : undefined,
    state: f.state === 'open' ? undefined : f.state,
    through: f.through == null ? undefined : String(f.through),
  }
}

export function isRouteFiltered(f: RouteFilters): boolean {
  return Object.values(routeFiltersToQuery(f)).some((v) => v !== undefined)
}

export function parseRouteOrder(query: LocationQuery): RouteOrder {
  return strings(query.order)[0] === 'last_seen' ? 'last_seen' : 'severity'
}

export const parseRouteId = (query: LocationQuery): number | null => id(query.route)
export const parseTarget = (query: LocationQuery): number => id(query.target) ?? 1

export function parsePage(query: LocationQuery): number {
  const page = Number(strings(query.page)[0])
  return Number.isInteger(page) && page > 1 ? page : 1
}

/** The list request's filter parameters (GET /attack-paths and its facets). */
export function routeApiFilters(f: RouteFilters) {
  return {
    severity: f.severity,
    kind: f.kind,
    cls: f.confidence,
    connection_id: f.connection ?? undefined,
    crossing: f.crossing && f.connection != null,
    state: f.state === 'fixed' ? ('resolved' as const) : ('open' as const),
    through: f.through ?? undefined,
  }
}
