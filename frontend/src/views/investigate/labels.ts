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

/** A web link as short text (2026-10-31 review): its site and the start of its path,
 * "docs.aws.amazon.com › lambda › …". The full address goes in the link's title. */
export function shortLink(href: string): string {
  try {
    const url = new URL(href)
    const host = url.hostname.replace(/^www\./, '')
    const parts = url.pathname.split('/').filter(Boolean).map((p) => {
      try {
        return decodeURIComponent(p)
      } catch {
        return p
      }
    })
    const shown = parts.slice(0, 2)
    return [host, ...shown, ...(parts.length > 2 ? ['…'] : [])].join(' › ')
  } catch {
    return href
  }
}

/** What a finding row leads with: Prowler's result for this resource ("Root account does not
 * have a hardware MFA device enabled"), not the check's passing condition. Other tools, and a
 * finding with no result sentence, keep the title. `check` is the title when the result leads. */
/** The list a finding belongs to: a CVE's is Vulnerabilities, any other's Misconfigurations. */
export function findingRoute(tool: string): 'vulnerabilities' | 'misconfigurations' {
  return tool === 'vulnerabilities' ? 'vulnerabilities' : 'misconfigurations'
}

export function findingLine(f: { tool: string; title: string; detail?: string | null }): { lead: string; check: string | null } {
  const detail = f.detail?.trim()
  return f.tool === 'prowler' && detail ? { lead: detail, check: f.title } : { lead: f.title, check: null }
}
