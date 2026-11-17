/**
 * An IAM role's use, in words (spec frontend/4ace4163, migration 0053): AWS's record of its last
 * use and how many workloads run as it. Missing data says why, never a zero; idle is not a
 * severity, so these are words only, no colour.
 */
import type { components } from '@/api/schema'

export type RoleUse = components['schemas']['RoleUse']

/** The UTC day of an ISO timestamp (YYYY-MM-DD), as the list shows every date. */
export function utcDay(iso: string): string {
  return new Date(iso).toISOString().slice(0, 10)
}

const DAY_MS = 86_400_000

/** The day a role never used was created: no recorded use, and created inside AWS's tracking
 * window counted back from the reading (owner, 2026-11-18). Null when it was used, is older than
 * the window ("not used in 400 days" then holds), or its creation is not known. */
export function neverUsedSince(use: RoleUse): string | null {
  if (use.last_used_at != null || use.observed_on == null || use.created_at == null) return null
  const created = utcDay(use.created_at)
  const age = (Date.parse(`${use.observed_on}T00:00:00Z`) - Date.parse(`${created}T00:00:00Z`)) / DAY_MS
  return age < use.tracking_days ? created : null
}

/** Last use for the panel: "2026-10-02 · us-east-1", "Never used · created 2026-11-12", "Not in
 * the last 400 days", or not read. */
export function lastUsedText(use: RoleUse): string {
  if (use.observed_on == null) return 'Not collected yet'
  const since = neverUsedSince(use)
  if (since) return `Never used · created ${since}`
  if (use.last_used_at == null) return `Not in the last ${use.tracking_days} days`
  const day = utcDay(use.last_used_at)
  return use.last_used_region ? `${day} · ${use.last_used_region}` : day
}

/** The workload count for the panel: "2 run as it", "None", or not counted. */
export function workloadsText(use: RoleUse): string {
  if (use.workloads == null) return 'Not counted yet'
  if (use.workloads === 0) return 'None'
  return `${use.workloads} run${use.workloads === 1 ? 's' : ''} as it`
}

/** The list's sub line, as segments joined by " · " (they may wrap). */
export function roleUseLine(use: RoleUse): string[] {
  const since = neverUsedSince(use)
  const used =
    use.observed_on == null
      ? 'Last use not collected yet'
      : since
        ? 'Never used'
        : use.last_used_at == null
          ? `Not used in ${use.tracking_days} days`
          : `Last used ${utcDay(use.last_used_at)}`
  const parts = [used]
  if (since) parts.push(`created ${since}`)
  if (use.last_used_at != null && use.last_used_region) parts.push(use.last_used_region)
  if (use.workloads == null) parts.push('workloads not counted yet')
  else if (use.workloads === 0) parts.push('no workload')
  else parts.push(`${use.workloads} workload${use.workloads === 1 ? '' : 's'}`)
  return parts
}

/** The sub line's title: where the value comes from and when it was read. */
export function roleUseTitle(use: RoleUse): string {
  const read = use.observed_on ? `, read ${use.observed_on}` : ''
  return `AWS's record of the role's last use${read}. AWS keeps the trailing ${use.tracking_days} days.`
}
