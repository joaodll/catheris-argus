/**
 * Why Argus gives a finding its reach, in words (docs/ui/screens.md, E7; ADR-0035, sixth
 * amendment): CloudFox's public endpoints and Prowler's exposure checks carry what Argus's
 * internet rules say about their resource, and a reason code. Shared by the reach badge's
 * tooltip and a finding's "Argus's verdict" block.
 */
export type FindingReach = 'confirmed' | 'restricted' | 'unknown' | 'not_covered'

/** The Findings Reach filter's options, in the order the front doors list uses. */
export const FINDING_REACHES: FindingReach[] = ['confirmed', 'unknown', 'restricted', 'not_covered']
export const FINDING_REACH_LABEL: Record<FindingReach, string> = {
  confirmed: 'Reachable',
  unknown: 'Unknown',
  restricted: 'Restricted',
  not_covered: 'Not checked',
}

const WORDS: Record<string, string> = {
  not_running: 'Not running: nothing listens until it starts.',
  block_public_access: 'S3 Block Public Access keeps anonymous requests out of its public policy.',
  no_public_address: 'No public address on the interface its security groups open.',
  sg_no_public_source: 'No security group opens a port it serves to the whole internet.',
  nacl_blocks: "The subnet's network ACL blocks the internet.",
  no_internet_route: 'No route to an internet gateway.',
  cidr_allowlist: 'Limited to listed source addresses.',
  iam_auth: 'Requires IAM authentication.',
  inspection_route: 'Its default route goes to a firewall endpoint, whose rules Argus does not read.',
  missing_data: 'A security group, route table or network ACL the verdict needs was not collected.',
  no_door: "Argus's internet rules found no way in (a terminated instance, for one).",
  not_in_inventory: 'Not in the inventory Argus judged: Steampipe has not collected it.',
}
// With no reason: what the reach alone says.
const BY_REACH: Record<FindingReach, string> = {
  confirmed: 'Argus found a way in: traffic from the internet can arrive.',
  restricted: 'Security groups, routing, a network ACL, auth or an address list keep the internet out.',
  unknown: WORDS.missing_data!,
  not_covered: 'No Argus rule checks this kind of resource.',
}

/** The reason in words; a code this page does not know is shown as itself (mono). */
export function reasonWords(reach: FindingReach, reason: string | null | undefined): { text: string; mono: boolean } {
  if (!reason) return { text: BY_REACH[reach], mono: false }
  const words = WORDS[reason]
  return words ? { text: words, mono: false } : { text: reason, mono: true }
}

/** Why the tool and Argus differ, on Restricted or Unknown; null otherwise. */
export function toolNote(tool: string, reach: FindingReach): string | null {
  if (reach !== 'restricted' && reach !== 'unknown') return null
  if (tool === 'prowler') return "Prowler flags an open security group whatever the instance's state, addresses, routes and network ACL; Argus checks each of them."
  if (tool === 'cloudfox') return 'CloudFox calls an endpoint public from its settings; Argus checks security groups, routing, network ACLs, auth and address lists.'
  return null
}

/** Whether the resource sheet has evidence to show: a door Argus judged (not no_door). */
export function hasEvidence(reach: FindingReach, reason: string | null | undefined): boolean {
  return reach !== 'not_covered' && reason !== 'no_door'
}
