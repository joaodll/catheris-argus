/**
 * A door's evidence in words (ADR-0035, fifth amendment): per network interface, the address
 * families it is public in, what its security groups open to the whole internet per family,
 * and each subnet's default route and network ACL. Shown under a front door's why-line, on the
 * map's link from the internet and in the resource sheet.
 */
import type { Schemas } from '@/api/client'

export type DoorInterface = Schemas['DoorInterface']
export type DoorSubnet = Schemas['DoorSubnet']

const FAMILY: Record<string, string> = { ipv4: 'IPv4', ipv6: 'IPv6' }
export const familyLabel = (f: string): string => FAMILY[f] ?? f

// Where a subnet's default route goes, by the target's id prefix.
const TARGET: [string, string][] = [
  ['nat-', 'NAT gateway'],
  ['tgw-', 'transit gateway'],
  ['vpce-', 'firewall endpoint'],
  ['pcx-', 'peering connection'],
  ['eni-', 'network interface'],
  ['i-', 'instance'],
  ['eigw-', 'egress-only gateway'],
  ['vgw-', 'VPN gateway'],
  ['lgw-', 'local gateway'],
  ['cagw-', 'carrier gateway'],
]

export function routeWords(route: string): string {
  if (route === 'igw') return 'default route to an internet gateway'
  if (route === 'none') return 'no default route'
  if (route === 'unknown') return 'route table not collected'
  const kind = TARGET.find(([prefix]) => route.startsWith(prefix))?.[1]
  return kind ? `default route to a ${kind} (${route})` : `default route to ${route}`
}

export function aclWords(acl: string | null): string {
  if (acl === 'allows') return 'network ACL lets it in'
  if (acl === 'blocks') return 'network ACL blocks it'
  if (acl === 'unknown') return 'network ACL not collected'
  return 'nothing open for the network ACL to check'
}

/** "eni-0a1 · public IPv4", "This resource · no public address". */
export function interfaceTitle(n: DoorInterface): string {
  const name = n.interface ?? 'This resource'
  const pub = n.public.length ? `public ${n.public.map(familyLabel).join(' and ')}` : 'no public address'
  return `${name} · ${pub}`
}

/** "IPv4: tcp/22, icmp · IPv6: nothing". */
export function openWords(n: DoorInterface): string {
  return (['ipv4', 'ipv6'] as const).map((f) => `${familyLabel(f)}: ${n.open[f].length ? n.open[f].join(', ') : 'nothing'}`).join(' · ')
}

/** One subnet's line: "subnet-0a1 (IPv4): default route to an internet gateway; network ACL lets it in". */
export function subnetWords(s: DoorSubnet): string {
  return `${s.subnet} (${familyLabel(s.family)}): ${routeWords(s.route)}; ${aclWords(s.acl)}`
}

/** Families an interface's groups open to the internet but it has no public address of. */
export function openWithoutAddress(network: DoorInterface[]): { family: string; ports: string[] }[] {
  const found: { family: string; ports: string[] }[] = []
  for (const f of ['ipv4', 'ipv6'] as const) {
    const ports = [...new Set(network.filter((n) => !n.public.includes(f)).flatMap((n) => n.open[f]))]
    if (ports.length && !network.some((n) => n.public.includes(f) && n.open[f].length)) found.push({ family: f, ports })
  }
  return found
}

const ICMP = /^icmp(v6)?(\/|$)/
export const onlyIcmp = (ports: string[]): boolean => ports.length > 0 && ports.every((p) => ICMP.test(p))

const STATE: Record<string, string> = { stopped: 'Stopped', stopping: 'Stopping', pending: 'Starting' }
export const stateWord = (state: string): string => STATE[state] ?? state
