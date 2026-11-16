/**
 * The map's state in the URL (ADR-0051): the focus on the canvas, the depth, the kinds of
 * connection drawn, Map or List, the open resource and the connection. Defaults
 * are left out, so a link reproduces the view. Nodes added by Expand or from a group are not in
 * the URL: after a reload the user sees the focus and its neighbourhood again. A value the page
 * does not know is ignored, so a link from the first map (?path=, ?highlight=, ?flow=) opens the
 * start screen or its focus.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'

export const LAYERS = ['traffic', 'identity', 'network', 'policy', 'data'] as const
export type Layer = (typeof LAYERS)[number]
// Every kind but Data access (owner, 2026-11-14): a resource opens with its network, role and
// policies; Data access fans out to many resources. The API's relationships.DEFAULT_LAYERS.
export const DEFAULT_LAYERS: Layer[] = ['traffic', 'identity', 'network', 'policy']
export const LAYER_LABEL: Record<Layer, string> = { traffic: 'Traffic', identity: 'Identity', network: 'Network', policy: 'IAM policy', data: 'Data access' }

// Hops one read walks around the focus (the API's MAX_DEPTH). Expand always adds one hop.
export const DEPTHS = [1, 2, 3] as const
export type Depth = (typeof DEPTHS)[number]

// The Map's view mode (round M, owner 2026-11-15, decisions/0faa077c): Infrastructure ('resource')
// draws no security line or fact and reads only the plain routes; Security does (ADR-0051). In the
// URL as mode=security; Infrastructure is the default and left out.
export type MapKind = 'resource' | 'security'
// The View switch's three segments: the two maps, and the Attack Path view (W6 §11.1), lit only
// while a route is open (mode=attack&route=<id>), which draws one stored route's steps and
// nothing else. Its cards are the Security view's.
export type ViewMode = MapKind | 'attack'

export type View = 'map' | 'list'

// The open resource's tab in the panel (spec frontend/d37cd13b); Overview is left out of the URL.
export const PANEL_TABS = ['overview', 'problems', 'routes', 'connections', 'configuration'] as const
export type PanelTab = (typeof PANEL_TABS)[number]

export interface MapState {
  focus: string | null
  depth: Depth
  layers: Layer[]
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
  tab: PanelTab
  mode: ViewMode
  // The Attack Path view's route, its listed target (1 is the worst) and the player's step.
  // Null and 1 in the other views: a route belongs to the Attack Path view only.
  route: number | null
  target: number
  step: number
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
  const view = one(query.view)
  const depth = Number(one(query.depth))
  const rawType = one(query.type)
  const type = rawType && rawType.length <= TYPE_MAX ? rawType : null
  return {
    focus: uid(query.focus),
    depth: (DEPTHS as readonly number[]).includes(depth) ? (depth as Depth) : 1,
    layers: layers.length ? layers : [...DEFAULT_LAYERS],
    view: view === 'map' || view === 'list' ? view : defaultView,
    open: uid(query.open),
    connection: id(query.connection),
    type,
    // A page belongs to a type's list.
    page: type ? (id(query.page) ?? 1) : 1,
    tab: (PANEL_TABS as readonly string[]).includes(one(query.tab) ?? '') ? (one(query.tab) as PanelTab) : 'overview',
    ...viewMode(query),
  }
}

/** mode=attack needs a readable route; without one it is the Security view (§11.1). */
function viewMode(query: LocationQuery): Pick<MapState, 'mode' | 'route' | 'target' | 'step'> {
  const mode = one(query.mode)
  const route = id(query.route)
  if (mode === 'attack' && route != null) return { mode, route, target: id(query.target) ?? 1, step: id(query.step) ?? 1 }
  return { mode: mode === 'security' || mode === 'attack' ? 'security' : 'resource', route: null, target: 1, step: 1 }
}

export function mapQueryToUrl(s: MapState, defaultView: View = 'map'): LocationQueryRaw {
  const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v, i) => v === b[i])
  const layers = ordered(s.layers, LAYERS)
  return {
    focus: s.focus ?? undefined,
    depth: s.depth === 1 ? undefined : String(s.depth),
    layer: same(layers, DEFAULT_LAYERS) ? undefined : layers,
    view: s.view === defaultView ? undefined : s.view,
    open: s.open ?? undefined,
    connection: s.connection == null ? undefined : String(s.connection),
    type: s.type ?? undefined,
    page: s.type == null || s.page === 1 ? undefined : String(s.page),
    tab: s.tab === 'overview' ? undefined : s.tab,
    mode: s.mode === 'resource' ? undefined : s.mode,
    ...(s.mode === 'attack' && s.route != null
      ? { route: String(s.route), target: s.target === 1 ? undefined : String(s.target), step: s.step === 1 ? undefined : String(s.step) }
      : {}),
  }
}

/** Nothing chosen in the Layers multi-select means every layer (the multi-select's "All"). */
export function chosenLayers(values: string[]): Layer[] {
  const layers = ordered(values as Layer[], LAYERS)
  return layers.length ? layers : [...LAYERS]
}

/** The graph request's parameters (GET /map/graph, or /map/security/graph for the Security
 * Map): `depth` hops around a focus, in one connection: the one the first response
 * walked (an Expand), else the URL's, else the API picks the focus's. */
export function graphParams(
  s: MapState,
  focus: string,
  { connection = s.connection, depth = s.depth }: { connection?: number | null; depth?: Depth } = {},
) {
  // Both sources are always drawn (owner, 2026-11-14): the API's default.
  return { focus, depth, layer: s.layers, connection_id: connection ?? undefined }
}
