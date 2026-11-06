/**
 * Summary | List on the Investigate screens (owner's decision 2026-11-05): the tab lives in the
 * URL (?tab=). An explicit tab wins. Without one, any other parameter (a filter, the order, the
 * page, a finding's own link) means the list, so every link made before the tabs existed still
 * opens the list it was made for; the bare screen opens the summary.
 */
import type { LocationQuery } from 'vue-router'

export type Tab = 'summary' | 'list'
export const TABS: Tab[] = ['summary', 'list']

export function parseTab(query: LocationQuery): Tab {
  const tab = Array.isArray(query.tab) ? query.tab[0] : query.tab
  if (tab === 'summary' || tab === 'list') return tab
  const listParams = Object.entries(query).filter(([key, value]) => key !== 'tab' && value != null && value !== '')
  return listParams.length ? 'list' : 'summary'
}

/** The summary's account: the list's connection when it names exactly one, else all (0). */
export function summaryConnection(connections: number[]): number {
  return connections.length === 1 ? (connections[0] ?? 0) : 0
}
