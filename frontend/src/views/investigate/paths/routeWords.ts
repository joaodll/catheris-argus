/**
 * The Attack paths screen's words (ADR-0052; spec W6 §1.3, §3.3 and its R2 delta §10): a route's
 * title and sub line, each step's move as a phrase and a sentence, why a step has its level (its
 * reason key), its facts and how to break it. Ported from the old screen's pathWords.ts and
 * pathText.ts (d0fb438), now read from stored route steps. A step carries only the attributes
 * ROUTE_STEP_ATTRIBUTES allows, so a sentence that needs another key falls back to its reason.
 * Every name from a scanned cloud is returned as text, for text interpolation only.
 */
import type { Schemas } from '@/api/client'
import { edgeWord } from '../edgeWords'
import { uidTail } from '../labels'
import { typeLabel } from '../map/mapLanes'
import { LEVEL_MEANING, type StepLevel } from './routeClass'
import { portLabel, sortPorts } from './ports'

export type NodeRef = Schemas['NodeRef']
export type StepOut = Schemas['StepOut']
export type StepNode = Schemas['StepNode']
export type RouteOut = Schemas['RouteOut']

/** Names the page knows: a connection by id, and the connection that scans an account. */
export interface Names {
  connection: (id: number) => string
  ofAccount: (account: string) => string | null
}

export const FOOTHOLD = 'FOOTHOLD'
export const AUTHENTICATES = 'AUTHENTICATES'
const INTERNET = 'internet'

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])
const text = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null)

/** "a", "a and b", "a, b and c". */
export function list(values: string[]): string {
  if (values.length <= 1) return values[0] ?? ''
  return `${values.slice(0, -1).join(', ')} and ${values[values.length - 1]}`
}

// A pseudo-node scoped to its connection by the walk ("any:dynamodb@1"): the part before the @.
const unscoped = (uid: string): string => uid.replace(/@\d+$/, '')
const accountOf = (uid: string): string | null => /^admin:(\d{12})/.exec(uid)?.[1] ?? null

/** A step's resource, or pseudo-node, as a type eyebrow and a name (W6 §1.3, the old words). */
export function nodeLabel(node: Pick<NodeRef, 'uid' | 'kind' | 'name' | 'type' | 'resource_id'>, names: Names): { type: string; name: string } {
  const uid = unscoped(node.uid)
  if (node.kind === 'internet') return { type: 'Entry point', name: 'Internet' }
  if (node.kind === 'admin') {
    const account = accountOf(uid) ?? uid.replace(/^admin:/, '')
    const conn = names.ofAccount(account)
    return { type: 'Administrator', name: `Administrator of ${conn ?? `account ${account}`}` }
  }
  if (uid === 'any:ssm') return { type: 'Systems Manager', name: 'Instances it manages' }
  if (node.kind === 'any') return { type: 'Wildcard grant (*)', name: `Every ${uid.replace(/^any:/, '')} resource` }
  if (node.kind === 'external') return { type: 'Not in the inventory', name: uid.replace(/^external:/, '') }
  if (node.resource_id == null) return { type: 'Not in the inventory', name: node.name || outsiderName(uid) }
  return { type: typeLabel(node.type), name: node.name || uidTail(uid) }
}

/** A principal not in the inventory by name: "Anyone", "Account 210987654321", an OpenID Connect
 * provider's host, or its ARN's last part. */
export function outsiderName(uid: string): string {
  if (uid === '*') return 'Anyone'
  const root = /^arn:aws[\w-]*:iam::(\d{12}):root$/.exec(uid)
  if (root) return `Account ${root[1]}`
  if (/^\d{12}$/.test(uid)) return `Account ${uid}`
  const provider = /:oidc-provider\/(.+)$/.exec(uid)
  if (provider) return provider[1]!
  return uidTail(uid)
}

/** The account a node is in, by connection name, for "in <account>". Null when Argus can't
 * tell, and for an administrator, whose name already says its account. */
export function accountName(node: Pick<NodeRef, 'uid' | 'kind' | 'connection_id'>, names: Names): string | null {
  if (node.kind === 'admin') return null
  if (node.connection_id != null) return names.connection(node.connection_id)
  // Every store of a service, scoped by the walk to one connection: "any:dynamodb@3".
  const scoped = node.kind === 'any' ? /@(\d+)$/.exec(node.uid) : null
  return scoped ? names.connection(Number(scoped[1])) : null
}

/** "<Kind name>: <entry name>" (§10.1). A kind this release has no file for is named by its id. */
export function routeTitle(r: Pick<RouteOut, 'kind' | 'kind_name' | 'entry'>, names: Names): string {
  return `${r.kind_name ?? `Route kind ${r.kind}`}: ${nodeLabel(r.entry, names).name}`
}

const many = (n: number, one: string, more: string): string => `${n.toLocaleString('en-US')} ${n === 1 ? one : more}`

/** The row's sub line (W6 §1.3): "Worst: <target> in <account> · 14 targets · crosses 2 accounts". */
export function routeSubline(r: Pick<RouteOut, 'worst_target' | 'target_count' | 'crossed_connection_ids'>, names: Names): string {
  const target = nodeLabel(r.worst_target, names).name
  const account = accountName(r.worst_target, names)
  const where = account ? `${target} in ${account}` : target
  const parts = [r.target_count === 1 ? `To ${where}` : `Worst: ${where}`]
  if (r.target_count > 1) parts.push(many(r.target_count, 'target', 'targets'))
  const others = r.crossed_connection_ids.length - 1
  if (others > 0) parts.push(`crosses ${many(others, 'other account', 'other accounts')}`)
  return parts.join(' · ')
}

/** The Accounts column's sub line: "+ crosses Shared, Data", at most two names then "+3"; the
 * whole list goes in the title. Null when the route stays in its entry's account. */
export function crossesLine(r: Pick<RouteOut, 'connection_id' | 'crossed_connection_ids'>, names: Names): { text: string; title: string } | null {
  const others = r.crossed_connection_ids.filter((id) => id !== r.connection_id).map(names.connection)
  if (!others.length) return null
  const shown = others.slice(0, 2).join(', ')
  const more = others.length > 2 ? ` +${others.length - 2}` : ''
  return { text: `+ crosses ${shown}${more}`, title: `Crosses ${list(others)}` }
}

// ---- steps ------------------------------------------------------------------------------------

// What keeps the internet out, in words (the internet rules' reason).
const CONTROL: Record<string, string> = {
  not_running: 'not running',
  no_public_address: 'no public address',
  no_internet_route: 'no internet route',
  nacl_blocks: 'network ACL',
  sg_no_public_source: 'security groups',
  cidr_allowlist: 'address allowlist',
  iam_auth: 'IAM authentication',
  block_public_access: 'Block Public Access',
}
export const controlWord = (reason: unknown): string => CONTROL[String(reason)] ?? 'a control'

/** Why a step has its level, by its reason key (§10.5). Every key the walk writes has one; a key
 * this release doesn't know falls back to its level's meaning. */
export const REASON: Record<string, string> = {
  internet_rule: "Argus's internet rules checked the way in: security groups, routes and network ACLs.",
  internet_cloudfox: 'Only CloudFox calls it public; no Argus rule confirms the reach.',
  internet_unknown: "Argus can't tell whether the internet reaches it: data it needs is missing.",
  anyone: 'Its trust lets anyone in any AWS account in.',
  outsider: "Its trust names a principal outside the scanned accounts: Argus can't see who controls it.",
  credential: "Whoever holds this user's credential acts as the user. Argus can't tell whether it leaked.",
  cloudfox_analysis: 'CloudFox analysed the policies and found it.',
  admin_policy: 'Its policies allow every action on every resource.',
  trust: "The role's trust policy allows it. IAM conditions and SCPs are not evaluated.",
  trust_condition: "The trust has a condition Argus doesn't evaluate.",
  trust_external_id: 'The trust requires an external id: Argus assumes whoever moves here has it.',
  cross_account_trust: "The trust names a principal in another account. Argus reads the trust, not that principal's own policy.",
  account_admin: "The trust names its account's root, so the account's administrator may assume it.",
  account_identity: "This principal may call sts:AssumeRole on the role (matched by name), and the trust names its account's root.",
  cross_account_admin: "The trust names another scanned account's root, so that account's administrator may assume it.",
  cross_account_identity:
    "This principal, in another scanned account, may call sts:AssumeRole on the role (matched by name), and the trust names its account's root.",
  escalation: 'Its policies grant what an escalation needs, matched by permission name. Conditions and boundaries are not evaluated.',
  configuration: 'The configuration connects them.',
  api_integration: "The API's integration sends requests to it.",
  manual: 'Someone added this connection by hand.',
  lateral: 'Its security groups admit the port from a private range. That a service answers is assumed.',
  ssm: 'It may send commands through Systems Manager, matched by permission name.',
  resource_side_unevaluated: "Its policies allow the access. The store's own policy is not evaluated.",
  trigger_input: 'Whoever can feed the source triggers the next step. Who can is not evaluated.',
  trigger_public_write: 'The source is public, so anyone can feed it and trigger the next step.',
  compromise_imdsv1: "IMDSv1 is on: a foothold reads its role's credentials.",
  compromise_assumed: 'Assumed: no evidence of a way in.',
  data_auth_assumed: 'Assumed: no evidence of database credentials on the way.',
}

const CVE = /^CVE-\d{4}-\d{4,}$/

/** A step's reason in words. */
export function reasonLine(step: Pick<StepOut, 'reason' | 'level' | 'ref'>): string {
  if (step.reason === 'compromise_cve') return CVE.test(step.ref) ? `A public exploit: ${step.ref}.` : 'A public exploit.'
  if (step.reason.startsWith('internet_restricted:')) {
    return `Argus found it closed to the internet (${controlWord(step.reason.slice('internet_restricted:'.length))}). One change would open this route.`
  }
  return REASON[step.reason] ?? LEVEL_MEANING[step.level as StepLevel]
}

/** The CVE a foothold step rests on, to link to Vulnerabilities; null otherwise. */
export const footholdCve = (step: Pick<StepOut, 'reason' | 'ref'>): string | null => (step.reason === 'compromise_cve' && CVE.test(step.ref) ? step.ref : null)

/** What the internet gets in on, from a door's allow-listed attributes. */
export function doorPorts(step: Pick<StepOut, 'type' | 'origin' | 'attributes'>): string[] {
  const a = step.attributes
  const rule = step.origin.startsWith('rule:')
  if (rule && step.type === 'ROUTES_TO') return sortPorts(strings(a.open))
  if (rule && (step.type === 'PUBLIC_RESTRICTED' || step.type === 'PUBLIC_UNVERIFIED')) {
    const network = Array.isArray(a.network) ? (a.network as { open?: { ipv4?: unknown; ipv6?: unknown } }[]) : []
    const open = network.flatMap((n) => [...strings(n?.open?.ipv4), ...strings(n?.open?.ipv6)])
    return sortPorts([...(step.type === 'PUBLIC_RESTRICTED' ? strings(a.open_ports) : []), ...open])
  }
  if (step.type === 'INTERNET_REACHABLE') {
    const protocol = String(a.protocol ?? '').toLowerCase() === 'udp' ? 'udp/' : 'tcp/'
    const raw = text(a.ports) ?? (typeof a.port === 'number' ? String(a.port) : text(a.port)) ?? ''
    const ports = raw
      .split(',')
      .map((p) => p.trim())
      .filter((p) => /^\d{1,5}(-\d{1,5})?$/.test(p))
    return sortPorts(ports.map((p) => protocol + p))
  }
  return []
}

const named = (ports: string[]): string => list(ports.map(portLabel))

const SERVICE: Record<string, string> = {
  ssh: 'SSH',
  rdp: 'RDP',
  winrm: 'WinRM',
  postgresql: 'PostgreSQL',
  postgres: 'PostgreSQL',
  'aurora-postgresql': 'Aurora PostgreSQL',
  mysql: 'MySQL',
  'aurora-mysql': 'Aurora MySQL',
  mariadb: 'MariaDB',
  sqlserver: 'SQL Server',
  oracle: 'Oracle',
  redis: 'Redis',
  memcached: 'Memcached',
  mongodb: 'MongoDB',
}
const serviceName = (s: string): string => SERVICE[s] ?? s
const portOf = (p: unknown): string => (typeof p === 'number' ? portLabel(`tcp/${p}`) : portLabel(String(p)))

// Escalation methods in AWS's own case (the rules match them lower-cased).
const ACTION_CASE: Record<string, string> = Object.fromEntries(
  [
    'iam:CreatePolicyVersion',
    'iam:SetDefaultPolicyVersion',
    'iam:AttachUserPolicy',
    'iam:AttachGroupPolicy',
    'iam:AttachRolePolicy',
    'iam:PutUserPolicy',
    'iam:PutGroupPolicy',
    'iam:PutRolePolicy',
    'iam:UpdateAssumeRolePolicy',
    'iam:CreateAccessKey',
    'iam:CreateLoginProfile',
    'iam:UpdateLoginProfile',
    'iam:AddUserToGroup',
    'iam:PassRole',
    'lambda:UpdateFunctionCode',
    'lambda:CreateFunction',
    'ec2:RunInstances',
    'cloudformation:CreateStack',
    'glue:CreateDevEndpoint',
    'ecs:RunTask',
  ].map((a) => [a.toLowerCase(), a]),
)
/** "iam:passrole+ec2:runinstances" -> "iam:PassRole + ec2:RunInstances". */
export const methodName = (method: string): string =>
  method
    .split('+')
    .map((a) => ACTION_CASE[a.toLowerCase()] ?? a)
    .join(' + ')

const ACCESS: Record<string, { short: string; word: string }> = {
  read: { short: 'can read', word: 'read' },
  write: { short: 'can write', word: 'write' },
  full: { short: 'has full access to', word: 'full' },
}

const OUTSIDER_KIND: Record<string, { short: string; who: string }> = {
  anyone: { short: 'anyone', who: 'anyone in any AWS account' },
  oidc_no_subject: { short: 'any token', who: 'any token from its OpenID Connect provider, with no condition on the subject' },
}

export interface Move {
  short: string // on the link
  sentence: string // in Evidence and fix
}

/** One move as a phrase and a sentence. A walk-made step (a foothold, a login) is not a move. */
export function moveWords(step: Pick<StepOut, 'type' | 'origin' | 'attributes' | 'source' | 'target'>): Move {
  const a = step.attributes
  if (step.source.uid === INTERNET) {
    if (step.type === 'OUTSIDER') {
      const account = text(a.account)
      const o = OUTSIDER_KIND[String(a.kind)] ?? { short: account ? `account ${account}` : 'another account', who: account ? `another account (${account})` : 'another account' }
      return { short: `outsider: ${o.short}`, sentence: `Someone outside the account controls this principal: ${o.who}.` }
    }
    if (step.type === 'HAS_CREDENTIAL') {
      const which = strings(a.credentials)
      const key = which.includes('access_key')
      const password = which.includes('console_password_no_mfa')
      const short = key && password ? 'with a leaked key or password' : password ? 'with a leaked console password' : 'with a leaked access key'
      return { short, sentence: "Whoever holds this user's credential acts as the user." }
    }
    if (step.type === 'PUBLIC_UNVERIFIED') return { short: 'may reach it', sentence: "Argus can't tell whether the internet reaches it." }
    if (step.type === 'PUBLIC_RESTRICTED') return { short: `kept out: ${controlWord(a.reason)}`, sentence: 'Argus found it closed to the internet: one change would open this route.' }
    if (a.via === 'resource_policy') return { short: 'anyone may use it', sentence: 'Its own policy lets anyone use it.' }
    if (step.type === 'ROUTES_TO' || step.type === 'INTERNET_REACHABLE') {
      const ports = doorPorts(step)
      return ports.length
        ? { short: `reaches it on ${named(ports)}`, sentence: `The internet reaches it on ${named(ports)}.` }
        : { short: 'reaches it', sentence: 'The internet reaches it.' }
    }
  }
  switch (step.type) {
    case 'ROUTES_TO':
      return { short: edgeWord(step.type), sentence: 'Traffic it receives goes on to the next step.' }
    case 'TRIGGERS':
      return { short: edgeWord(step.type), sentence: 'It starts the next step with what it receives.' }
    case 'RUNS_AS':
      return { short: edgeWord(step.type), sentence: "It runs with this role's permissions." }
    case 'CAN_ASSUME':
      return { short: edgeWord(step.type), sentence: 'It may assume the next role.' }
    case 'ACCESSES': {
      const level = ACCESS[String(a.level)] ?? ACCESS.read!
      return { short: level.short, sentence: `Its policies allow ${level.word} access to the next step.` }
    }
    case 'IS_ADMIN':
      return { short: edgeWord(step.type), sentence: 'Its policies allow every action on every resource.' }
    case 'CAN_PRIVESC_TO':
      return { short: 'can escalate (CloudFox)', sentence: 'CloudFox found it can make itself an administrator.' }
    case 'CAN_ESCALATE_TO': {
      const methods = strings(a.methods).map(methodName)
      if (!methods.length) return { short: 'can escalate', sentence: 'It can make itself an administrator.' }
      const more = methods.length > 1 ? ` and ${methods.length - 1} more` : ''
      return { short: `can escalate via ${methods[0]}${more}`, sentence: `It can make itself an administrator: its policies allow ${list(methods)}.` }
    }
    case 'CAN_CONNECT_TO': {
      const services = list(strings(a.services).map(serviceName))
      const ports = list((Array.isArray(a.ports) ? a.ports : []).map(portOf))
      const admits = ports ? `: its security groups admit ${ports} from a private range` : ''
      return {
        short: services ? `can connect over ${services}` : 'can connect to',
        sentence: `From here an attacker can open ${services || 'a connection'} on the next step${admits}.`,
      }
    }
    case 'CAN_RUN_ON':
      return step.target.uid.startsWith('any:ssm')
        ? { short: edgeWord(step.type, step.target.uid), sentence: 'It may send commands or start sessions through Systems Manager.' }
        : { short: edgeWord(step.type, step.target.uid), sentence: 'Systems Manager manages this instance and reaches it.' }
  }
  const words = edgeWord(step.type, step.target.uid)
  return { short: words, sentence: `${words.charAt(0).toUpperCase()}${words.slice(1)}.` }
}

/** A walk-made step's heading (§3.3, §10.3): "Takes control of web-1", "Logs in to orders-db". */
export function selfStepTitle(step: Pick<StepOut, 'type'>, name: string): string {
  return step.type === AUTHENTICATES ? `Logs in to ${name}` : `Takes control of ${name}`
}

export interface Fact {
  label: string
  value: string
  mono?: boolean
  title?: string
}

const UNEVALUATED: Record<string, string> = {
  resources: 'which resources',
  conditions: 'conditions',
  boundaries: 'permission boundaries',
  scps: 'SCPs',
  deny: 'Deny statements',
  unlisted_aws_managed_policies: "AWS-managed policies outside Argus's list",
}
const CHECKED: Record<string, string> = {
  security_groups: 'security groups',
  route_table: 'route table',
  network_acl: 'network ACL',
  dns_chain: 'DNS records',
  resource_policy: "the resource's policy",
}
const IMDS: Record<string, string> = { v1: 'IMDSv1: no token required', v2: 'IMDSv2 only', off: 'Off' }
const REACHED: Record<string, string> = {
  public_ip: 'a public address',
  private_address: 'a private address',
  load_balancer: 'a load balancer',
  database: 'a database endpoint',
  api: 'an API',
  cdn: 'a CloudFront distribution',
  dns: 'a DNS record',
  function_url: 'a function URL',
  kubernetes_api: 'the Kubernetes API endpoint',
  resource_policy: 'its own policy',
}
// A door's own evidence: in its reach line and evidence block, not repeated as facts.
const DOOR_BLOCK = new Set(['network', 'reason', 'missing', 'state'])
const PORT_KEYS = new Set(['ports', 'port', 'open', 'open_ports', 'protocol'])
const joined = (values: string[]): string => values.join(', ')
const raw = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v))

/** A step's allow-listed attributes in words; a key the screen does not name shows as it is. */
export function factsOf(step: Pick<StepOut, 'type' | 'origin' | 'attributes' | 'source'>): Fact[] {
  const a = step.attributes
  const fromInternet = step.source.uid === INTERNET
  const facts: Fact[] = []
  const ports = fromInternet ? doorPorts(step) : (Array.isArray(a.ports) ? a.ports : []).map((p) => (typeof p === 'number' ? `tcp/${p}` : String(p)))
  if (ports.length) facts.push({ label: 'Ports', value: joined(ports.map(portLabel)), mono: true })
  for (const [key, value] of Object.entries(a)) {
    if (PORT_KEYS.has(key) || (fromInternet && DOOR_BLOCK.has(key))) continue
    const values = strings(value)
    switch (key) {
      case 'services':
        facts.push({ label: 'Services', value: joined(values.map(serviceName)) })
        break
      case 'engine':
        facts.push({ label: 'Engine', value: serviceName(raw(value)) })
        break
      case 'methods':
        facts.push({ label: 'Escalation methods', value: joined(values.map(methodName)), mono: true })
        break
      case 'level':
        facts.push({ label: 'Access', value: { read: 'Read', write: 'Write', full: 'Full' }[String(value)] ?? raw(value) })
        break
      case 'via_policy':
        facts.push({ label: 'Allowed by policies', value: joined(values.map(uidTail)), title: joined(values), mono: true })
        break
      case 'via':
        if (Array.isArray(value)) facts.push({ label: 'Allowed by', value: joined(values.map((v) => (v.startsWith('arn:') ? uidTail(v) : v))), title: joined(values), mono: true })
        else facts.push(REACHED[String(value)] ? { label: 'Reached through', value: REACHED[String(value)]! } : { label: 'Reached through', value: raw(value), mono: true })
        break
      case 'credentials':
        facts.push({ label: 'Credentials', value: joined(values.map((c) => ({ access_key: 'Active access key', console_password_no_mfa: 'Console password without MFA' })[c] ?? c)) })
        break
      case 'routes':
        facts.push({ label: 'Routes', value: joined(values), mono: true })
        break
      case 'kind':
        facts.push(step.type === 'OUTSIDER' ? { label: 'Outsider', value: { other_account: 'Another account', anyone: 'Anyone', oidc_no_subject: 'An OpenID Connect provider with no subject condition' }[String(value)] ?? raw(value) } : { label: key, value: raw(value), mono: true })
        break
      case 'account':
        facts.push({ label: 'Account', value: raw(value), mono: true })
        break
      case 'imds':
        facts.push({ label: 'Instance metadata', value: IMDS[String(value)] ?? raw(value) })
        break
      case 'unevaluated':
        facts.push({ label: 'Not evaluated', value: joined(values.map((u) => UNEVALUATED[u] ?? u)) })
        break
      case 'checked':
        facts.push({ label: 'Argus checked', value: joined(values.map((c) => CHECKED[c] ?? c)) })
        break
      case 'waf':
        facts.push({ label: 'WAF', value: value === true ? 'A web ACL protects it' : 'None' })
        break
      case 'dns':
        facts.push({ label: 'DNS', value: raw(value), mono: true })
        break
      default:
        facts.push({ label: key, value: raw(value), mono: true })
    }
  }
  return facts
}

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
  FOOTHOLD: 'Patch what gives a way in (the CVE named here), require IMDSv2, and keep the workload off the internet where it need not be.',
  AUTHENTICATES: 'Use IAM authentication or short-lived database credentials, and keep them out of the workloads on the way.',
}
const NETWORK_CLOSED = new Set(['not_running', 'no_public_address', 'no_internet_route', 'nacl_blocks'])

/** "Break this link": one sentence for a step. */
export function breakLink(step: Pick<StepOut, 'type' | 'source' | 'target' | 'attributes'>): string {
  const { type } = step
  const fromInternet = step.source.uid === INTERNET
  if (type === 'ROUTES_TO' && fromInternet && step.attributes.via === 'resource_policy') return 'Remove the statement for "*" from its policy, or name the accounts that may use it.'
  if (type === 'INTERNET_REACHABLE' || (type === 'ROUTES_TO' && fromInternet)) return 'Remove public access, or put authentication in front of this endpoint.'
  if (type === 'PUBLIC_UNVERIFIED') return "Let Argus read what is missing (the scanner role's permissions, then a new Steampipe scan); if it is reachable, remove public access."
  if (type === 'PUBLIC_RESTRICTED') {
    if (NETWORK_CLOSED.has(String(step.attributes.reason))) return 'Already closed. Keep the control that closes it, and close what its security groups open, so one change cannot open this route.'
    return `Already closed by ${controlWord(step.attributes.reason)}. Keep it on, so one change cannot open this route.`
  }
  if (type === 'ROUTES_TO') return 'Stop routing this traffic here, or require authentication at the previous step.'
  return BREAK[type] ?? 'Review whether this connection is needed.'
}

// ---- the chain --------------------------------------------------------------------------------

export type ChainItem =
  | { kind: 'node'; node: StepNode; key: string }
  | { kind: 'link'; step: StepOut; key: string }
  | { kind: 'self'; step: StepOut; key: string }

/** The steps in walk order as a chain (§10.3): step 1's source, then per step a link and its
 * target, or a walk-made step (source = target: a foothold, a login) on the resource it stands on. */
export function chainItems(steps: StepOut[]): ChainItem[] {
  if (!steps.length) return []
  const out: ChainItem[] = [{ kind: 'node', node: steps[0]!.source, key: `n0-${steps[0]!.source.uid}` }]
  for (const s of steps) {
    if (s.source.uid === s.target.uid) out.push({ kind: 'self', step: s, key: `s${s.n}` })
    else out.push({ kind: 'link', step: s, key: `l${s.n}` }, { kind: 'node', node: s.target, key: `n${s.n}-${s.target.uid}` })
  }
  return out
}
