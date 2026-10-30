/**
 * The Attack paths filters and the URL (docs/ui/screens.md, E12), as on Findings: every filter
 * in the query string, defaults left out, a value the page does not know ignored. ?path=<id>
 * opens one path in place of the table; ?through=<uid> arrives from a resource panel.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { SEVERITIES, type Severity } from '@/views/overview/severity'
import { CONFIDENCES, type Confidence } from './confidence'

export type PathState = 'open' | 'resolved'
export type PathOrder = 'severity' | 'first_seen_desc' | 'first_seen_asc' | 'last_seen_desc' | 'last_seen_asc'

export interface PathFilters {
  severity: Severity[]
  category: string[]
  // The kinds (their file ids), finer than a category (2026-10-23).
  kind: string[]
  // How sure (ADR-0037); it replaced the rule filter: one search finds every kind of path.
  confidence: Confidence[]
  connection: number | null
  state: PathState
  through: string | null
}

const ORDERS: PathOrder[] = ['severity', 'first_seen_desc', 'first_seen_asc', 'last_seen_desc', 'last_seen_asc']
const LIST_MAX = 50 // as the API
const TEXT_MAX = 128
const UID_MAX = 2048
const KIND = /^[a-z0-9][a-z0-9-]{0,63}$/ // as the API

function strings(value: LocationQuery[string] | undefined): string[] {
  const all = Array.isArray(value) ? value : value == null ? [] : [value]
  return [...new Set(all.filter((v): v is string => typeof v === 'string' && v !== ''))].slice(0, LIST_MAX)
}

function id(value: LocationQuery[string] | undefined): number | null {
  const n = Number(strings(value)[0])
  return Number.isInteger(n) && n > 0 ? n : null
}

export function parsePathFilters(query: LocationQuery): PathFilters {
  const through = strings(query.through)[0] ?? null
  return {
    severity: strings(query.severity).filter((s): s is Severity => (SEVERITIES as readonly string[]).includes(s)),
    category: strings(query.category).filter((c) => c.length <= TEXT_MAX),
    kind: strings(query.kind).filter((k) => KIND.test(k)),
    confidence: CONFIDENCES.filter((c) => strings(query.confidence).includes(c)),
    connection: id(query.connection),
    state: strings(query.state)[0] === 'resolved' ? 'resolved' : 'open',
    through: through && through.length <= UID_MAX ? through : null,
  }
}

export function pathFiltersToQuery(f: PathFilters): LocationQueryRaw {
  const list = (values: string[]) => (values.length ? values : undefined)
  return {
    severity: list(f.severity),
    category: list(f.category),
    kind: list(f.kind),
    confidence: list(f.confidence),
    connection: f.connection == null ? undefined : String(f.connection),
    state: f.state === 'open' ? undefined : f.state,
    through: f.through ?? undefined,
  }
}

export function parsePathOrder(query: LocationQuery): PathOrder {
  const value = strings(query.order)[0] as PathOrder
  return ORDERS.includes(value) ? value : 'severity'
}

export function parsePathId(query: LocationQuery): number | null {
  return id(query.path)
}

export function parsePage(query: LocationQuery): number {
  const page = Number(strings(query.page)[0])
  return Number.isInteger(page) && page > 1 ? page : 1
}

export function isPathFiltered(f: PathFilters): boolean {
  return Object.values(pathFiltersToQuery(f)).some((v) => v !== undefined)
}

/** The list request's filter parameters (GET /attack-paths). */
export function pathApiFilters(f: PathFilters) {
  return { severity: f.severity, category: f.category, kind: f.kind, confidence: f.confidence, connection_id: f.connection, state: f.state, through: f.through }
}

/** The next order when a date column's header is clicked: newest first, then oldest first. */
export function toggleDate(order: PathOrder, column: 'first_seen' | 'last_seen'): PathOrder {
  return order === `${column}_desc` ? `${column}_asc` : `${column}_desc`
}
