/** Wording shared by the Findings and Resources pages (docs/ui/screens.md, E7 and E8). */

/** "Global" for the region tools report for account-wide resources and checks. */
export function regionLabel(region: string): string {
  return region === 'global' ? 'Global' : region
}

/** The short form of a uid shown in a cell: its last segment, after the last "/" or ":". */
export function uidTail(uid: string): string {
  const cut = Math.max(uid.lastIndexOf('/'), uid.lastIndexOf(':'))
  const tail = cut >= 0 ? uid.slice(cut + 1) : uid
  return tail || uid
}

export type FindingState = 'open' | 'reopened' | 'resolved' | 'accepted_risk'

/** An edge's origin as a chip word: rules carry their id and version in the tooltip. */
export function originLabel(origin: string): string {
  if (origin.startsWith('rule:')) return 'Rule'
  if (origin === 'cloudfox') return 'CloudFox'
  if (origin === 'manual') return 'Manual'
  if (origin === 'probe') return 'Probe'
  return origin
}

/** Resource types grouped by service for the type filter (~400 Steampipe tables, argus_v8):
 * aws_ec2_instance -> "aws ec2". Groups and types in name order. */
export function typesByService(types: string[]): { service: string; types: string[] }[] {
  const groups = new Map<string, string[]>()
  for (const type of [...types].sort()) {
    const [provider = type, service] = type.split('_')
    const key = service ? `${provider} ${service}` : provider
    groups.set(key, [...(groups.get(key) ?? []), type])
  }
  return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([service, list]) => ({ service, types: list }))
}

export function fromSelect(value: string): string | null {
  return value === '' ? null : value
}

/** A link from tool output (a remediation guide), only when it is a web address: anything else
 * (a javascript: URL in a crafted report) is not rendered as a link. */
export function webUrl(value: string | null | undefined): string | null {
  if (!value) return null
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null
  } catch {
    return null
  }
}
