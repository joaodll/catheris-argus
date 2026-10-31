/**
 * Where each Overview number leads (docs/ui/screens.md, Overview "Drill-downs"): the list that
 * holds it, with the filters that reproduce it, built with each list's own URL helpers so the
 * URL format lives in one place. connectionId 0 is All connections: no connection filter (the
 * lists then also show disabled connections, which the Overview leaves out).
 */
import type { RouteLocationRaw } from 'vue-router'
import { emptyFilters, filtersToQuery } from '@/views/investigate/findingFilters'
import { pathFiltersToQuery, parsePathFilters } from '@/views/investigate/paths/pathFilters'
import type { Severity } from './severity'

// The Overview's failed-findings counts: Prowler, failed, not muted, still open (metric_daily
// findings.open_by_severity).
export function failedFindings(connectionId: number, severity: Severity): RouteLocationRaw {
  const query = filtersToQuery({
    ...emptyFilters(),
    severity: [severity],
    tool: ['prowler'],
    result: ['FAIL'],
    muted: 'hide',
    connection: connectionId ? [connectionId] : [],
  })
  return { name: 'misconfigurations', query }
}

export function attackPaths(connectionId: number, filter: { severity?: Severity[]; category?: string }): RouteLocationRaw {
  const query = pathFiltersToQuery({
    ...parsePathFilters({}),
    severity: filter.severity ?? [],
    category: filter.category ? [filter.category] : [],
    connection: connectionId || null,
  })
  return { name: 'attack-paths', query }
}

export function resources(connectionId: number, type?: string): RouteLocationRaw {
  return { name: 'resources', query: { connection: connectionId ? String(connectionId) : undefined, type } }
}

export const THREATSCORE_FRAMEWORK = 'prowler_threatscore_aws' // findings/metrics.py

export function framework(connectionId: number, key: string): RouteLocationRaw {
  return { name: 'framework', params: { framework: key }, query: { connection: connectionId ? String(connectionId) : undefined } }
}

export function threatScore(connectionId: number): RouteLocationRaw {
  return framework(connectionId, THREATSCORE_FRAMEWORK)
}
