/** The collectors Argus runs against an account, in the order their runs are queued
 * (collection/collect.py TOOL_ORDER): one list for every screen that names them. Inspector
 * collects AWS Inspector's vulnerabilities (ADR-0042). */
export const COLLECTORS = [
  { id: 'steampipe', name: 'Steampipe' },
  { id: 'prowler', name: 'Prowler' },
  { id: 'cloudfox', name: 'CloudFox' },
  { id: 'inspector', name: 'Inspector' },
] as const

export type Collector = (typeof COLLECTORS)[number]['id']

export const COLLECTOR_IDS: Collector[] = COLLECTORS.map((c) => c.id)

export function collectorName(id: string): string {
  return COLLECTORS.find((c) => c.id === id)?.name ?? id
}
