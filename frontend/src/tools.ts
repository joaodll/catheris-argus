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

/** The tools Run now and a new schedule start ticked (owner's decision, 2026-10-31): Steampipe,
 * Prowler and CloudFox always; Inspector only when its latest run on every chosen connection
 * finished (complete or partial), so an account without Inspector gets no failed run. */
export function defaultTools(lastRuns: { connection_id: number; tool: string; status: string }[], connectionIds: number[]): Collector[] {
  const ran = (id: number): boolean =>
    lastRuns.some((r) => r.connection_id === id && r.tool === 'inspector' && (r.status === 'complete' || r.status === 'partial'))
  const inspector = connectionIds.length > 0 && connectionIds.every(ran)
  return COLLECTOR_IDS.filter((t) => t !== 'inspector' || inspector)
}
