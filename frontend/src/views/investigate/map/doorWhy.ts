/** Why a front door has its reach, in one line of the front doors list (ADR-0035). */
import type { Schemas } from '@/api/client'
import { familyLabel, onlyIcmp, openWithoutAddress, stateWord } from './doorEvidence'

type Door = Pick<
  Schemas['FrontDoor'],
  'reach' | 'reason' | 'sources' | 'missing' | 'open' | 'families' | 'open_ports' | 'listens' | 'default_routes' | 'network' | 'state' | 'policy_actions'
>

// Why a restricted door is closed, from its rule's reason and the sources it admits: with
// sources, "<lead>: a, b, c and N more"; without, `closed` when the reason has one.
const REASON: Record<string, { lead: string; closed?: string }> = {
  sg_no_public_source: { lead: 'Security groups admit only', closed: 'No security group is open to the internet on a port it serves' },
  nacl_blocks: { lead: 'Network ACL admits only', closed: 'Network ACL blocks the internet on its open ports' },
  no_internet_route: { lead: 'No route to an internet gateway' },
  cidr_allowlist: { lead: 'Limited to source addresses' },
  iam_auth: { lead: 'Requires IAM authentication' },
  no_public_address: { lead: 'No public address' },
  not_running: { lead: 'Not running' },
}
// What an unknown door is missing, in words: "route_table:subnet-0a1" -> "route table for subnet-0a1".
const MISSING: Record<string, string> = {
  security_group: 'security group',
  security_group_rules: 'rules of security group',
  route_table: 'route table for',
  network_acl: 'network ACL for',
}
// A resource public by its own policy (ADR-0037, second amendment): what its policy lets anyone do.
const POLICY_CONDITION = 'policy_condition:'
const S3_ACCOUNT = 's3_account_settings:'
const policy = (d: Door): string => `Its policy lets anyone ${list(d.policy_actions)}`
const FAMILY: Record<string, string> = { ipv4: 'IPv4', ipv6: 'IPv6' }
const DNS_TARGET = 'dns_target:'
const INSPECTION = 'inspection_route:'

// "external:status.vendor.example.net" -> the host; an ARN -> its last part ("static.example.com").
function endName(target: string): string {
  if (target.startsWith('external:')) return target.slice('external:'.length)
  return target.split(/[/:]/).filter(Boolean).pop() ?? target
}

export function list(values: string[]): string {
  const shown = values.slice(0, 3).join(', ')
  return `${shown}${values.length > 3 ? ` and ${values.length - 3} more` : ''}`
}

/** What its groups open to the internet, against what it serves (ADR-0035, fourth amendment). */
function opened(d: Door): string | null {
  if (!d.open_ports.length) return null
  const serves = d.listens?.length ? `, but it listens on ${list(d.listens)}` : ''
  return `Security groups open ${list(d.open_ports)} to the internet${serves}`
}

/** "Opens tcp/22 to ::/0 (IPv6); it has no IPv6 address" (ADR-0035, fifth amendment). */
function openElsewhere(d: Door): string | null {
  const [first] = openWithoutAddress(d.network)
  if (!first) return null
  const anywhere = first.family === 'ipv6' ? '::/0' : '0.0.0.0/0'
  const label = familyLabel(first.family)
  return `Opens ${list(first.ports)} to ${anywhere} (${label}); it has no public ${label} address`
}

function restricted(d: Door): string {
  if (d.reason === 'block_public_access') {
    return `${d.policy_actions.length ? policy(d) : 'Public by its own policy'}, but S3 Block Public Access keeps anonymous requests out`
  }
  const reason = d.reason ? REASON[d.reason] : undefined
  if (!reason) return 'Security groups, routing, auth or an address list keep the internet out'
  if (d.reason === 'not_running') {
    const state = d.state ? stateWord(d.state) : 'Not running'
    return `${state}, though its security groups open ${list(d.open_ports)} to the internet`
  }
  if (d.reason === 'no_public_address') {
    // Several interfaces: the open group sits on one with no public address (fifth amendment).
    const open = d.network.find((n) => !n.public.length && (n.open.ipv4.length || n.open.ipv6.length))
    if (d.network.length > 1 && open?.interface) {
      return `Its security groups open ${list(d.open_ports)} to the internet on ${open.interface}, which has no public address`
    }
    return `No public address, though its security groups open ${list(d.open_ports)} to the internet`
  }
  // Nothing open in the families it has an address of: say what is open in one it lacks.
  if (d.reason === 'sg_no_public_source' && !d.sources.length && !d.open_ports.length) {
    const elsewhere = openElsewhere(d)
    if (elsewhere) return elsewhere
  }
  if (d.reason === 'sg_no_public_source' && !d.sources.length) {
    if (onlyIcmp(d.open_ports)) return `Only ${list(d.open_ports)} (ping) is open to the internet; no port that serves anything`
  }
  if (d.reason === 'no_internet_route') {
    const routes = d.default_routes.filter((r) => r !== 'none')
    const where = routes.length ? `; the default route goes to ${list(routes)}` : d.default_routes.length ? '; there is no default route' : ''
    return `${reason.lead}${where}`
  }
  if (d.sources.length) return `${reason.lead}: ${list(d.sources)}`
  if (d.reason === 'sg_no_public_source' && d.listens?.length) return opened(d) ?? reason.closed ?? reason.lead
  if (d.reason === 'nacl_blocks' && d.open_ports.length) return `${opened(d)}; the network ACL blocks it`
  return reason.closed ?? reason.lead
}

/** An unknown door's open ports, from its evidence: "; its security groups open tcp/22". */
function opens(d: Door): string {
  const ports = [...new Set(d.network.flatMap((n) => [...n.open.ipv4, ...n.open.ipv6]))]
  return ports.length ? `; its security groups open ${list(ports)}` : ''
}

export function doorWhy(d: Door): string | null {
  if (d.reach === 'cloudfox_only') {
    // CloudFox names the ports; it does not check source ranges or routes (ADR-0035).
    const ports = d.open.length ? ` (${list(d.open)})` : ''
    return `Only CloudFox calls it public${ports}; no Argus rule confirms it`
  }
  if (d.reach === 'open' && d.policy_actions.length) return policy(d)
  if (d.reach === 'open') {
    const families = d.families.map((f) => FAMILY[f] ?? f).join(' and ')
    return [list(d.open), families].filter(Boolean).join(' · ') || null
  }
  if (d.reach === 'unknown') {
    if (d.missing.includes('subnet')) return "Argus can't tell: no subnet is recorded for it"
    // A DNS record whose chain ends at what Argus does not judge (internet-dns, argus_v12).
    const ends = d.missing.filter((m) => m.startsWith(DNS_TARGET)).map((m) => endName(m.slice(DNS_TARGET.length)))
    if (ends.length) return `Points to ${list(ends)}, which Argus does not check`
    // A default route to a firewall or Gateway Load Balancer endpoint (ADR-0035, fourth amendment).
    const inspected = d.missing.filter((m) => m.startsWith(INSPECTION)).map((m) => m.slice(INSPECTION.length))
    if (inspected.length) return `Argus can't tell: ${list(inspected)} routes the internet through a firewall endpoint, whose rules Argus does not read${opens(d)}`
    const accounts = d.missing.filter((m) => m.startsWith(S3_ACCOUNT)).map((m) => m.slice(S3_ACCOUNT.length))
    if (accounts.length) return `Argus can't tell: the account's S3 Block Public Access settings (${list(accounts)}) were not collected`
    if (d.policy_actions.length && d.missing.some((m) => m.startsWith(POLICY_CONDITION))) {
      return `${policy(d)}, under a condition Argus does not evaluate`
    }
    const gaps = d.missing.map((m) => {
      const at = m.indexOf(':')
      return at < 0 ? m : `${MISSING[m.slice(0, at)] ?? m.slice(0, at)} ${m.slice(at + 1)}`
    })
    return `Argus can't tell: ${gaps.length ? `${list(gaps)} not collected` : 'data is missing'}${opens(d)}`
  }
  return restricted(d)
}

const EDGE_REACH: Partial<Record<string, Door['reach']>> = { ROUTES_TO: 'open', PUBLIC_RESTRICTED: 'restricted', PUBLIC_UNVERIFIED: 'unknown' }
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

/** A door as its internet rule's edge holds it (the resource sheet): null for any other edge. */
export function doorOfEdge(edge: { type: string; origin: string; attributes: Record<string, unknown> }): Door | null {
  const reach = EDGE_REACH[edge.type]
  if (!reach || !edge.origin.startsWith('rule:')) return null
  const a = edge.attributes
  return {
    reach,
    reason: typeof a.reason === 'string' ? a.reason : null,
    sources: strings(a.sources),
    missing: strings(a.missing),
    open: strings(a.open),
    families: strings(a.families),
    open_ports: strings(a.open_ports),
    listens: Array.isArray(a.listens) ? strings(a.listens) : null,
    default_routes: strings(a.default_routes),
    network: Array.isArray(a.network) ? (a.network as Door['network']) : [],
    state: typeof a.state === 'string' ? a.state : null,
    policy_actions: a.via === 'resource_policy' ? strings(a.actions) : [],
  }
}
