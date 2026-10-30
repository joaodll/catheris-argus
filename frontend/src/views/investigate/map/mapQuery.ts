/**
 * The Resource map's state in the URL (docs/ui/screens.md, E11): the front doors' connection,
 * filters and page; the flow or focus on the canvas, depth, layers, origins, day, view, a
 * highlighted path and the open resource. Defaults are left out, so a link reproduces the view. Nodes added by Expand or from a group are not in the URL: after a
 * reload the user sees the focus neighbourhood again. A value the page does not know is ignored.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'

export const LAYERS = ['traffic', 'identity', 'network', 'policy', 'data'] as const
export type Layer = (typeof LAYERS)[number]
export const DEFAULT_LAYERS: Layer[] = ['traffic', 'identity']
export const LAYER_LABEL: Record<Layer, string> = { traffic: 'Traffic', identity: 'Identity', network: 'Network', policy: 'IAM policy', data: 'Data access' }

// Manual joins these with the edge editor (ADR-0033: the seam is kept, the editor comes later).
export const ORIGINS = ['rule', 'cloudfox'] as const
export type Origin = (typeof ORIGINS)[number]
export const ORIGIN_LABEL: Record<Origin, string> = { rule: 'Rules', cloudfox: 'CloudFox' }

export type View = 'map' | 'list'
// What is on the canvas: a flow, the whole chain from an internet entry (ADR-0036); a
// neighbourhood around a focus (Explore, ADR-0033); or nothing, and the front doors list shows.
export type Mode = 'flow' | 'explore' | 'doors'
// A front door's reach (ADR-0035), as the API names it.
// In the list's order: an unknown door could be open, so it comes before the restricted ones.
export const REACHES = ['open', 'unknown', 'restricted', 'cloudfox_only'] as const
export type Reach = (typeof REACHES)[number]
export const REACH_LABEL: Record<Reach, string> = { open: 'Reachable', unknown: 'Unknown', restricted: 'Restricted', cloudfox_only: 'CloudFox only' }
const REGION_MAX = 64 // as the API
export const DEPTHS = [1, 2, 3] as const
export type Depth = (typeof DEPTHS)[number]

export interface MapState {
  flow: number | null
  focus: string | null
  depth: Depth
  layers: Layer[]
  origins: Origin[]
  asOf: string | null
  view: View
  path: number | null
  open: string | null
  // The connection the map walks (ADR-0033, amended 2026-10-09): the Front doors' choice, or
  // none, and then the API walks the focus resource's own connection.
  connection: number | null
  // The front doors list: its search, filters (none chosen: all) and page.
  q: string
  reach: Reach[]
  region: string[]
  page: number
}

/** A flow wins over a focus; with neither, the front doors list shows. */
export function modeOf(s: Pick<MapState, 'flow' | 'focus'>): Mode {
  return s.flow != null ? 'flow' : s.focus ? 'explore' : 'doors'
}

const UID_MAX = 2048 // as the API

function strings(value: LocationQuery[string] | undefined): string[] {
  const all = Array.isArray(value) ? value : value == null ? [] : [value]
  return [...new Set(all.filter((v): v is string => typeof v === 'string' && v !== ''))]
}

function one(value: LocationQuery[string] | undefined): string | null {
  return strings(value)[0] ?? null
}

function uid(value: LocationQuery[string] | undefined): string | null {
  const v = one(value)
  return v && v.length <= UID_MAX ? v : null
}

function id(value: LocationQuery[string] | undefined): number | null {
  const n = Number(one(value))
  return Number.isInteger(n) && n > 0 ? n : null
}

/** In the order of the full list, so the same choice is always the same URL. */
function ordered<T extends string>(chosen: readonly T[], all: readonly T[]): T[] {
  return all.filter((v) => chosen.includes(v))
}

export function parseMapQuery(query: LocationQuery, defaultView: View = 'map'): MapState {
  const depth = Number(one(query.depth))
  const layers = ordered(strings(query.layer) as Layer[], LAYERS)
  const origins = ordered(strings(query.origin) as Origin[], ORIGINS)
  const asOf = one(query.as_of)
  const view = one(query.view)
  // An older link's ?mode= is ignored: what is open says the mode (argus_v11).
  return {
    flow: id(query.flow),
    focus: uid(query.focus),
    depth: (DEPTHS as readonly number[]).includes(depth) ? (depth as Depth) : 1,
    layers: layers.length ? layers : [...DEFAULT_LAYERS],
    origins: origins.length ? origins : [...ORIGINS],
    asOf: asOf && /^\d{4}-\d{2}-\d{2}$/.test(asOf) ? asOf : null,
    view: view === 'map' || view === 'list' ? view : defaultView,
    path: id(query.path),
    open: uid(query.open),
    connection: id(query.connection),
    q: (one(query.q) ?? '').trim().slice(0, 200),
    reach: ordered(strings(query.reach) as Reach[], REACHES),
    region: strings(query.region).filter((r) => r.length <= REGION_MAX).sort(),
    page: id(query.page) ?? 1,
  }
}

export function mapQueryToUrl(s: MapState, defaultView: View = 'map'): LocationQueryRaw {
  const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v, i) => v === b[i])
  const layers = ordered(s.layers, LAYERS)
  const origins = ordered(s.origins, ORIGINS)
  return {
    flow: s.flow == null ? undefined : String(s.flow),
    focus: s.focus ?? undefined,
    depth: s.depth === 1 ? undefined : String(s.depth),
    layer: same(layers, DEFAULT_LAYERS) ? undefined : layers,
    origin: same(origins, ORIGINS) ? undefined : origins,
    as_of: s.asOf ?? undefined,
    view: s.view === defaultView ? undefined : s.view,
    path: s.path == null ? undefined : String(s.path),
    open: s.open ?? undefined,
    connection: s.connection == null ? undefined : String(s.connection),
    q: s.q || undefined,
    reach: s.reach.length ? ordered(s.reach, REACHES) : undefined,
    region: s.region.length ? [...s.region].sort() : undefined,
    page: s.page > 1 ? String(s.page) : undefined,
  }
}

/** Nothing chosen in the Layers multi-select means every layer (the multi-select's "All"). */
export function chosenLayers(values: string[]): Layer[] {
  const layers = ordered(values as Layer[], LAYERS)
  return layers.length ? layers : [...LAYERS]
}

/** The graph request's parameters (GET /map/graph), for one focus, in one connection: the
 * one the first response walked (an Expand), else the URL's, else the API picks the focus's. */
export function graphParams(s: MapState, focus: string, depth: number = s.depth, connection: number | null = s.connection) {
  return { focus, depth, layer: s.layers, origin: s.origins, as_of: s.asOf, connection_id: connection ?? undefined }
}
