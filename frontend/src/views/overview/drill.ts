/**
 * Where each Overview number leads (docs/ui/screens.md, Overview "Drill-downs"): the list that
 * holds it, with the filters that reproduce it, built with each list's own URL helpers so the
 * URL format lives in one place. connectionId 0 is All connections: no connection filter (the
 * lists then also show disabled connections, which the Overview leaves out).
 */
import type { RouteLocationRaw } from 'vue-router'
import { emptyFilters, filtersToQuery } from '@/views/investigate/findingFilters'
import { resourcesLink } from '@/views/investigate/resourceFilters'
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

// The Overview's asset counts (assets.total, assets.by_type) count asset types only, so the list
// they open does too (assets=1).
export function resources(connectionId: number, type?: string): RouteLocationRaw {
  return resourcesLink({ assets: true, connection: connectionId ? [connectionId] : [], type: type ? [type] : [] })
}

export const THREATSCORE_FRAMEWORK = 'prowler_threatscore_aws' // findings/metrics.py

export function framework(connectionId: number, key: string): RouteLocationRaw {
  return { name: 'framework', params: { framework: key }, query: { connection: connectionId ? String(connectionId) : undefined } }
}

export function threatScore(connectionId: number): RouteLocationRaw {
  return framework(connectionId, THREATSCORE_FRAMEWORK)
}

// The Overview's vulnerabilities card: the Vulnerabilities summary, same account.
export function vulnerabilitiesSummary(connectionId: number): RouteLocationRaw {
  return { name: 'vulnerabilities', query: { tab: 'summary', connection: connectionId ? String(connectionId) : undefined } }
}
