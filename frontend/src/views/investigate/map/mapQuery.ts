/**
 * The map's state in the URL (ADR-0051): the focus on the canvas, the depth, the kinds of
 * connection drawn, their sources, Map or List, the open resource and the connection. Defaults
 * are left out, so a link reproduces the view. Nodes added by Expand or from a group are not in
 * the URL: after a reload the user sees the focus and its neighbourhood again. A value the page
 * does not know is ignored, so a link from the first map (?path=, ?highlight=, ?flow=) opens the
 * start screen or its focus.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'

export const LAYERS = ['traffic', 'identity', 'network', 'policy', 'data'] as const
export type Layer = (typeof LAYERS)[number]
export const DEFAULT_LAYERS: Layer[] = ['traffic', 'identity']
export const LAYER_LABEL: Record<Layer, string> = { traffic: 'Traffic', identity: 'Identity', network: 'Network', policy: 'IAM policy', data: 'Data access' }

// Manual joins these with the edge editor (the seam is kept, the editor comes later).
export const ORIGINS = ['rule', 'cloudfox'] as const
export type Origin = (typeof ORIGINS)[number]
export const ORIGIN_LABEL: Record<Origin, string> = { rule: 'Rules', cloudfox: 'CloudFox' }

// Hops one read walks around the focus (the API's MAX_DEPTH). Expand always adds one hop.
export const DEPTHS = [1, 2, 3] as const
export type Depth = (typeof DEPTHS)[number]

// Which map: the Resource Map draws no security line; the Security Map does (ADR-0051).
export type MapKind = 'resource' | 'security'

export type View = 'map' | 'list'

export interface MapState {
  focus: string | null
  depth: Depth
  layers: Layer[]
  origins: Origin[]
  view: View
  open: string | null
  // The connection the map walks (one per read, ADR-0051), or none, and then the API
  // walks the focus resource's own connection. With no focus: the start screen's account, which
  // narrows its search.
  connection: number | null
  // The start screen's chosen type and its page. They stay while a map is open, so Back and the
  // way back to the start return to the same list.
  type: string | null
  page: number
}

const UID_MAX = 2048 // as the API
const TYPE_MAX = 128 // as the API

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
  const layers = ordered(strings(query.layer) as Layer[], LAYERS)
  const origins = ordered(strings(query.origin) as Origin[], ORIGINS)
  const view = one(query.view)
  const depth = Number(one(query.depth))
  const rawType = one(query.type)
  const type = rawType && rawType.length <= TYPE_MAX ? rawType : null
  return {
    focus: uid(query.focus),
    depth: (DEPTHS as readonly number[]).includes(depth) ? (depth as Depth) : 1,
    layers: layers.length ? layers : [...DEFAULT_LAYERS],
    origins: origins.length ? origins : [...ORIGINS],
    view: view === 'map' || view === 'list' ? view : defaultView,
    open: uid(query.open),
    connection: id(query.connection),
    type,
    // A page belongs to a type's list.
    page: type ? (id(query.page) ?? 1) : 1,
  }
}

export function mapQueryToUrl(s: MapState, defaultView: View = 'map'): LocationQueryRaw {
  const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v, i) => v === b[i])
  const layers = ordered(s.layers, LAYERS)
  const origins = ordered(s.origins, ORIGINS)
  return {
    focus: s.focus ?? undefined,
    depth: s.depth === 1 ? undefined : String(s.depth),
    layer: same(layers, DEFAULT_LAYERS) ? undefined : layers,
    origin: same(origins, ORIGINS) ? undefined : origins,
    view: s.view === defaultView ? undefined : s.view,
    open: s.open ?? undefined,
    connection: s.connection == null ? undefined : String(s.connection),
    type: s.type ?? undefined,
    page: s.type == null || s.page === 1 ? undefined : String(s.page),
  }
}

/** Nothing chosen in the Layers multi-select means every layer (the multi-select's "All"). */
export function chosenLayers(values: string[]): Layer[] {
  const layers = ordered(values as Layer[], LAYERS)
  return layers.length ? layers : [...LAYERS]
}

/** The graph request's parameters (GET /map/graph): `depth` hops around a focus on one map, in
 * one connection: the one the first response walked (an Expand), else the URL's, else the API
 * picks the focus's. */
export function graphParams(
  s: MapState,
  focus: string,
  { connection = s.connection, depth = s.depth, map = 'resource' }: { connection?: number | null; depth?: Depth; map?: MapKind } = {},
) {
  return { focus, depth, map, layer: s.layers, origin: s.origins, connection_id: connection ?? undefined }
}
