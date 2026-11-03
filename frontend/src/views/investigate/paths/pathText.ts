/** The Attack paths screen's sentences (docs/ui/screens.md, E12). */
import { SEVERITY_LABEL, type Severity } from '@/views/overview/severity'
import { controlWord } from './pathWords'

const BREAK: Record<string, string> = {
  ALLOWS_INGRESS: "Restrict the security group's inbound rule to known sources.",
  RUNS_AS: 'Give the resource a role with only the permissions it needs.',
  CAN_ASSUME: "Narrow the role's trust policy, and require an external id for other accounts.",
  CAN_PRIVESC_TO: 'Remove the permissions that let this role escalate (see its CloudFox finding).',
  IS_ADMIN: 'Replace administrator access with least-privilege permissions.',
  TRIGGERS: 'Restrict who can write to the source that triggers this function.',
  ACCESSES: 'Grant only the data access this principal needs, on named resources.',
  CAN_ESCALATE_TO: 'Remove the permissions named here, or limit them to resources that cannot grant more; a permissions boundary helps.',
  CAN_CONNECT_TO: 'Admit this port only from the sources that need it, not a whole private range.',
  CAN_RUN_ON: 'Limit ssm:SendCommand and ssm:StartSession to the instances and documents this principal needs.',
  OUTSIDER: "Remove the outside principal from the role's trust policy, or require an external id; for an OpenID Connect provider, add a condition on the token's subject.",
  HAS_CREDENTIAL: "Replace the user's access keys with roles or SSO, and require MFA for its console password.",
}
const FROM_INTERNET = 'Remove public access, or put authentication in front of this endpoint.'
const PUBLIC_POLICY = 'Remove the statement for "*" from its policy, or name the accounts that may use it.'
// A closed door: its groups still open something to the internet when something else (state,
// address, route, network ACL) keeps it out; otherwise the control itself is the fix.
const NETWORK_CLOSED = new Set(['not_running', 'no_public_address', 'no_internet_route', 'nacl_blocks'])
const KEEP_CLOSED = 'Already closed. Keep the control that closes it, and close what its security groups open, so one change cannot open this path.'
// Argus could not judge the entry: first let it see what is missing, then decide.
const UNVERIFIED = 'Let Argus read what is missing (the scanner role\'s permissions, then a new Steampipe scan); if it is reachable, remove public access.'

/** "Break this link": one sentence for an edge type. A security group is a MEMBER_OF target
 * that is not an IAM group; a door public by its own policy is fixed in that policy. */
export function breakLink(edge: { type: string; source_uid: string; target_uid: string; attributes: Record<string, unknown> }): string {
  const { type, source_uid: sourceUid, target_uid: targetUid } = edge
  if (type === 'ROUTES_TO' && sourceUid === 'internet' && edge.attributes.via === 'resource_policy') return PUBLIC_POLICY
  if (type === 'INTERNET_REACHABLE' || (type === 'ROUTES_TO' && sourceUid === 'internet')) return FROM_INTERNET
  if (type === 'PUBLIC_UNVERIFIED') return UNVERIFIED
  if (type === 'PUBLIC_RESTRICTED') {
    if (NETWORK_CLOSED.has(String(edge.attributes.reason))) return KEEP_CLOSED
    return `Already closed by ${controlWord(edge.attributes.reason)}. Keep it on, so one change cannot open this path.`
  }
  if (type === 'ROUTES_TO') return 'Stop routing this traffic here, or require authentication at the previous step.'
  if (type === 'MEMBER_OF' && !/:iam::\d{12}:group\//.test(targetUid)) {
    return 'Move the resource to a security group that does not allow this traffic.'
  }
  return BREAK[type] ?? 'Review whether this connection is needed.'
}

const word = (s: string | null): string => SEVERITY_LABEL[s as Severity] ?? s ?? ''

/** Why a path has its severity: its kind's level, raised one when Argus confirmed the internet
 * reaches the entry, lowered one when no resource on the path has a failing finding. Null for a
 * path evaluated before the reasons were stored. */
export function severityLine(p: { severity: string; base_severity: string | null; entry_confirmed: boolean | null; has_failing: boolean | null }): string | null {
  if (!p.base_severity) return null
  const reasons: string[] = []
  if (p.entry_confirmed) reasons.push('Argus confirmed the internet reaches the entry')
  if (p.has_failing === false) reasons.push('no resource on the path has a failing finding')
  const base = `${word(p.base_severity)} for its kind`
  const changed = p.severity === p.base_severity ? '' : `, ${rank(p.severity) < rank(p.base_severity) ? 'raised' : 'lowered'} to ${word(p.severity)}`
  if (reasons.length === 0) return `${base}${changed}.`
  return `${base}${changed}: ${reasons.join(', and ')}.`
}

const ORDER = ['critical', 'high', 'medium', 'low', 'informational']
function rank(s: string): number {
  const i = ORDER.indexOf(s)
  return i < 0 ? ORDER.length : i
}

/** A connection a path passes through (ADR-0044, M2). */
export interface PathAccount {
  connection_id: number
  name: string | null
}

function accountName(a: PathAccount): string {
  return a.name ?? `Connection ${a.connection_id}`
}

/** "prod → shared → dev": every account on the path, the entry's first. */
export function accountsChain(accounts: PathAccount[]): string {
  return accounts.map(accountName).join(' → ')
}

/** The Connection column's second line when a path leaves its entry's account: "Crosses into
 * shared", or "Crosses into 2 accounts"; the whole chain goes in the title. */
export function crossesLine(accounts: PathAccount[]): { text: string; title: string } | null {
  const others = accounts.slice(1)
  if (!others.length) return null
  const into = others.length === 1 ? accountName(others[0]!) : `${others.length} accounts`
  return { text: `Crosses into ${into}`, title: accountsChain(accounts) }
}

/** The list's note when its paths are behind the scans (owner's decision, 2026-11-01): the
 * graph has not evaluated the newest scans yet, or its last update failed. */
export function staleNote(
  graph: { evaluated_at: string | null; behind: boolean; failed: boolean },
  when: (iso: string) => string,
): { kind: 'info' | 'warn'; text: string } | null {
  const shown = graph.evaluated_at ? ` Shown: the paths found ${when(graph.evaluated_at)}.` : ''
  if (graph.failed) {
    return { kind: 'warn', text: `Attack paths may be out of date: updating them from the newest scans failed.${shown} Argus keeps retrying.` }
  }
  if (graph.behind) {
    return graph.evaluated_at
      ? { kind: 'info', text: `Attack paths are being updated from the newest scans.${shown}` }
      : { kind: 'info', text: 'Attack paths have not been evaluated from the newest scans yet.' }
  }
  return null
}

/** The list's note when the per-account cap kept found paths out of it (ADR-0044, amended
 * 2026-11-02). It has only counts by severity and entry account, so it doesn't describe a filtered
 * list; passing-through lists also show other accounts' paths, so it names where these enter. */
export function notListedNote(n: { paths: number; latent: number; worst: Severity | null } | null | undefined, account: string | null): string | null {
  if (!n || n.paths + n.latent === 0) return null
  const where = account ? ` entering ${account}` : ''
  const count = (total: number, word: string) => `${total.toLocaleString('en-US')} more ${word}${total === 1 ? '' : 's'}`
  const found = (total: number) => `${total === 1 ? 'was' : 'were'} found but not listed`
  const after = "Filters and counts here don't include them."
  if (n.paths === 0) return `${count(n.latent, 'latent path')}${where} ${found(n.latent)}. ${after}`
  const worst = n.worst === 'informational' ? SEVERITY_LABEL.informational : `${SEVERITY_LABEL[n.worst ?? 'informational']} or lower`
  const latent = n.latent ? `, plus ${n.latent.toLocaleString('en-US')} latent path${n.latent === 1 ? '' : 's'}` : ''
  return `${count(n.paths, 'path')}${where} ${found(n.paths)}: ${worst}${latent}. ${after}`
}
