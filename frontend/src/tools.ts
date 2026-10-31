/** The collectors Argus runs against an account, in the order their runs are queued
 * (collection/collect.py TOOL_ORDER): one list for every screen that names them. Vulnerabilities
 * collects each provider's own vulnerability scanner (ADR-0042): AWS Inspector on AWS. */
export const COLLECTORS = [
  { id: 'steampipe', name: 'Steampipe' },
  { id: 'prowler', name: 'Prowler' },
  { id: 'cloudfox', name: 'CloudFox' },
  { id: 'vulnerabilities', name: 'Vulnerabilities' },
] as const

export type Collector = (typeof COLLECTORS)[number]['id']

export const COLLECTOR_IDS: Collector[] = COLLECTORS.map((c) => c.id)

export function collectorName(id: string): string {
  return COLLECTORS.find((c) => c.id === id)?.name ?? id
}

/** The providers' vulnerability scanners behind the Vulnerabilities tool, by the `scanner` the
 * API reports. */
const SCANNERS: Record<string, string> = { 'aws-inspector': 'AWS Inspector' }

export function scannerName(id: string): string {
  return SCANNERS[id] ?? id
}

/** The tools Run now and a new schedule start ticked (owner's decision, 2026-10-31): Steampipe,
 * Prowler and CloudFox always; Vulnerabilities only when its latest run on every chosen
 * connection finished (complete or partial), so an account without a scanner enabled gets no
 * failed run. */
export function defaultTools(lastRuns: { connection_id: number; tool: string; status: string }[], connectionIds: number[]): Collector[] {
  const ran = (id: number): boolean =>
    lastRuns.some((r) => r.connection_id === id && r.tool === 'vulnerabilities' && (r.status === 'complete' || r.status === 'partial'))
  const vulnerabilities = connectionIds.length > 0 && connectionIds.every(ran)
  return COLLECTOR_IDS.filter((t) => t !== 'vulnerabilities' || vulnerabilities)
}
