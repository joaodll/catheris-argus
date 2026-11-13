/**
 * The Risk filters and the URL (ADR-0049), as the Investigate lists do it: every filter in the
 * query string, repeated for several values, defaults left out, so a tile's link reproduces its
 * count and a filtered list can be bookmarked, shared and restored by Back. A value the page does
 * not know is ignored, never sent. The open resource sheet (?open=) and the page are read apart.
 */
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import type { Schemas } from '@/api/client'
import { PROVIDERS, type Provider } from '@/providers'
import { ids, known, strings } from '@/views/investigate/findingFilters'

export type Tier = Schemas['RiskRow']['tier']
export type CombinationId = Schemas['RiskRow']['combinations'][number]

export const TIERS: Tier[] = ['critical', 'high', 'medium']
// The contract's order (risk/combinations.py), so chips and the By combination list read the same.
export const COMBINATION_IDS: CombinationId[] = [
  'reachable-exploitable',
  'admin-user-long-lived-credential',
  'reachable-critical-cve',
  'reachable-misconfigured',
  'reachable-secret',
  'exploitable-fixable',
]
const PROVIDER_IDS: Provider[] = PROVIDERS.map((p) => p.id)
const TYPE_MAX = 200 // as the API

export interface RiskFilters {
  // The account: one connection, or none for all (the tiles follow it).
  connection: number | null
  provider: Provider[]
  tier: Tier[]
  combination: CombinationId[]
  type: string[]
}

export function emptyRiskFilters(): RiskFilters {
  return { connection: null, provider: [], tier: [], combination: [], type: [] }
}

export function parseRiskFilters(query: LocationQuery): RiskFilters {
  return {
    connection: ids(query.connection)[0] ?? null,
    provider: known(query.provider, PROVIDER_IDS),
    tier: known(query.tier, TIERS),
    combination: known(query.combination, COMBINATION_IDS),
    type: strings(query.type, TYPE_MAX),
  }
}

/** The query string for these filters: defaults left out. */
export function riskFiltersToQuery(f: RiskFilters): LocationQueryRaw {
  const list = (values: string[]): string[] | undefined => (values.length ? values : undefined)
  return {
    connection: f.connection == null ? undefined : String(f.connection),
    provider: list(f.provider),
    tier: list(f.tier),
    combination: list(f.combination),
    type: list(f.type),
  }
}

/** The list request's filter parameters (GET /risk). */
export function riskApiFilters(f: RiskFilters) {
  return {
    connection_id: f.connection == null ? [] : [f.connection],
    provider: f.provider,
    tier: f.tier,
    combination: f.combination,
    type: f.type,
  }
}

/** Filters beyond the account: what Clear filters clears. */
export function isRiskFiltered(f: RiskFilters): boolean {
  return f.provider.length + f.tier.length + f.combination.length + f.type.length > 0
}

/** The Risk list with these filters (a tile's link, a combination's). */
export function riskLink(filters: Partial<RiskFilters>): { name: 'risk'; query: LocationQueryRaw } {
  return { name: 'risk', query: riskFiltersToQuery({ ...emptyRiskFilters(), ...filters }) }
}
