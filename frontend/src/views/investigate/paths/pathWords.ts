/**
 * The Attack paths screen's words for steps (docs/ui/screens.md, E12, 2026-10-23): how a path
 * gets in (the list's path line), each move as a phrase and a sentence, an edge's facts in
 * words, and the names of steps that are not a resource. Read from the edges' attributes, as
 * the rules and the CloudFox adapter write them (backend/rules/relationships).
 */
import { uidTail } from '../labels'
import { list } from '../map/doorWhy'
import { nodeName, type MapNode } from '../map/mapGraph'
import { typeLabel } from '../map/mapLanes'
import { portLabel, sortPorts } from './ports'

export interface StepEdge {
  type: string
  origin: string
  attributes: Record<string, unknown>
}
export interface ChainEdge extends StepEdge {
  source_uid: string
  target_uid: string
}

const INTERNET = 'internet'
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])
const text = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null)
const isRule = (e: StepEdge): boolean => e.origin.startsWith('rule:')
const byPolicy = (e: StepEdge): boolean => e.attributes.via === 'resource_policy'

/** What the internet gets in on, as attack-path kinds read a door (doors.py, view `d`): Argus's
 * verdict when it has one, CloudFox's ports only for its own endpoint. */
export function doorPorts(e: StepEdge): string[] {
  const a = e.attributes
  if (isRule(e) && e.type === 'ROUTES_TO') return sortPorts(strings(a.open))
  if (isRule(e) && (e.type === 'PUBLIC_RESTRICTED' || e.type === 'PUBLIC_UNVERIFIED')) {
    const network = Array.isArray(a.network) ? (a.network as { open?: { ipv4?: unknown; ipv6?: unknown } }[]) : []
    const open = network.flatMap((n) => [...strings(n?.open?.ipv4), ...strings(n?.open?.ipv6)])
    return sortPorts([...(e.type === 'PUBLIC_RESTRICTED' ? strings(a.open_ports) : []), ...open])
  }
  if (e.type === 'INTERNET_REACHABLE') {
    const protocol = String(a.protocol ?? '').toLowerCase() === 'udp' ? 'udp/' : 'tcp/'
    const raw = text(a.ports) ?? (typeof a.port === 'number' ? String(a.port) : text(a.port)) ?? ''
    const ports = raw.split(',').map((p) => p.trim()).filter((p) => /^\d{1,5}(-\d{1,5})?$/.test(p))
    return sortPorts(ports.map((p) => protocol + p))
  }
  return []
}

const named = (ports: string[]): string => list(ports.map(portLabel))

// What keeps the internet out, in the short form of the path line (attackpaths/confidence.py,
// BLOCKED_BY, has the long form).
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

const CREDENTIAL: Record<string, string> = { access_key: 'access key', console_password_no_mfa: 'console password without MFA' }
const credentials = (e: StepEdge): string[] => strings(e.attributes.credentials).map((c) => CREDENTIAL[c] ?? c)

function outsider(e: StepEdge): { short: string; who: string } {
  const account = text(e.attributes.account)
  if (e.attributes.kind === 'anyone') return { short: 'anyone', who: 'anyone in any AWS account' }
  if (e.attributes.kind === 'oidc_no_subject') return { short: 'any token', who: 'any token from its OpenID Connect provider, with no condition on the subject' }
  return { short: account ? `account ${account}` : 'another account', who: account ? `another account (${account})` : 'another account' }
}

/** How a path gets in, from its first step: "Exposed: tcp/22 (SSH)". Null for a step the
 * screen has no words for. */
export function wayIn(e: StepEdge | null | undefined): string | null {
  if (!e) return null
  if (e.type === 'OUTSIDER') {
    const kind = e.attributes.kind
    if (kind === 'anyone') return 'Outsider: anyone'
    if (kind === 'oidc_no_subject') return 'Outsider: any token from its OpenID Connect provider'
    return `Outsider: ${outsider(e).short}`
  }
  if (e.type === 'HAS_CREDENTIAL') {
    const which = credentials(e)
    return `Leaked credential: ${which.length ? which.join(' or ') : 'a credential'}`
  }
  const ports = doorPorts(e)
  const on = (lead: string): string => (ports.length ? `${lead}: ${named(ports)}` : lead)
  if (e.type === 'ROUTES_TO' && isRule(e) && byPolicy(e)) {
    const actions = strings(e.attributes.actions)
    return actions.length ? `Public by its policy: anyone may ${list(actions)}` : 'Public by its policy'
  }
  if ((e.type === 'ROUTES_TO' && isRule(e)) || e.type === 'INTERNET_REACHABLE') return on('Exposed')
  if (e.type === 'PUBLIC_UNVERIFIED') return on('Reach unknown')
  if (e.type === 'PUBLIC_RESTRICTED') return on(`Restricted (${controlWord(e.attributes.reason)})`)
  return null
}

/** The principal an outsider controls, by name: "Anyone", "Account 210987654321", an OpenID
 * Connect provider's host, or its ARN's last part. */
export function outsiderName(uid: string): string {
  if (uid === '*') return 'Anyone'
  const root = /^arn:aws[\w-]*:iam::(\d{12}):root$/.exec(uid)
  if (root) return `Account ${root[1]}`
  if (/^\d{12}$/.test(uid)) return `Account ${uid}`
  const provider = /:oidc-provider\/(.+)$/.exec(uid)
  if (provider) return provider[1]!
  return uidTail(uid)
}

/** "<entry name>" for a one-step path (the door is the path), else "entry → … → target · N
 * steps". */
export function whereItGoes(entry: string, target: string, nodes: number, sameEnds: boolean): string {
  if (sameEnds && nodes <= 2) return entry
  const steps = Math.max(0, nodes - 1)
  return `${entry} → … → ${target} · ${steps} ${steps === 1 ? 'step' : 'steps'}`
}

interface ListedPath {
  entry_uid: string
  target_uid: string
  entry_name: string | null
  target_name: string | null
  node_uids: string[]
  entry_step: StepEdge | null
}

// A node's kind from its uid, as the API's relationships.kind_of: a pseudo-node or a resource.
function kindOf(uid: string): MapNode['kind'] {
  if (uid === INTERNET) return 'internet'
  for (const kind of ['admin', 'external', 'any'] as const) if (uid.startsWith(`${kind}:`)) return kind
  return 'resource'
}
/** A path end by name: its inventory name, else as its step is named ("Admin · 1234…"). */
const endName = (uid: string, name: string | null, inbound: StepEdge | null): string =>
  name ?? stepLabel({ uid, kind: kindOf(uid), name: null, type: null, resource_id: null }, inbound).name

/** The list's path line: how it gets in, then where it goes. A path listed without its first
 * step keeps the line from before 2026-10-23. */
export function pathLine(p: ListedPath): string {
  const entry = endName(p.entry_uid, p.entry_name, p.entry_step)
  const target = endName(p.target_uid, p.target_name, null)
  const way = wayIn(p.entry_step)
  const where = whereItGoes(entry, target, p.node_uids.length, p.entry_uid === p.target_uid)
  return way ? `${way} · ${where}` : whereItGoes(entry, target, p.node_uids.length, false)
}

// Escalation methods in AWS's own case (privilege-escalation.toml matches them lower-cased).
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

const LEVEL: Record<string, { short: string; word: string }> = {
  read: { short: 'can read', word: 'read' },
  write: { short: 'can write', word: 'write' },
  full: { short: 'has full access to', word: 'full' },
}

export interface Move {
  short: string // on the link
  sentence: string // in Evidence and fix
}

/** One step as a phrase and a sentence (E12, Moves). */
export function moveWords(e: ChainEdge): Move {
  const a = e.attributes
  if (e.source_uid === INTERNET) {
    if (e.type === 'OUTSIDER') {
      const o = outsider(e)
      return { short: `outsider: ${o.short}`, sentence: `Someone outside the account controls this principal: ${o.who}.` }
    }
    if (e.type === 'HAS_CREDENTIAL') {
      const which = strings(a.credentials)
      const key = which.includes('access_key')
      const password = which.includes('console_password_no_mfa')
      const short = key && password ? 'with a leaked key or password' : password ? 'with a leaked console password' : 'with a leaked access key'
      const words = which.length ? credentials(e).join(' or ') : 'credential'
      return { short, sentence: `Whoever holds this user's ${words} acts as the user.` }
    }
    if (e.type === 'PUBLIC_UNVERIFIED') return { short: 'may reach it', sentence: "Argus can't tell whether the internet reaches it." }
    if (e.type === 'PUBLIC_RESTRICTED') {
      return { short: `kept out: ${controlWord(a.reason)}`, sentence: 'Argus found it closed to the internet: one change would open this path.' }
    }
    if (byPolicy(e)) {
      const actions = list(strings(a.actions))
      return { short: actions ? `anyone may ${actions}` : 'anyone may use it', sentence: actions ? `Its own policy lets anyone ${actions}.` : 'Its own policy lets anyone use it.' }
    }
    if (e.type === 'ROUTES_TO' || e.type === 'INTERNET_REACHABLE') {
      const ports = doorPorts(e)
      return ports.length
        ? { short: `reaches it on ${named(ports)}`, sentence: `The internet reaches it on ${named(ports)}.` }
        : { short: 'reaches it', sentence: 'The internet reaches it.' }
    }
  }
  switch (e.type) {
    case 'ROUTES_TO':
      return { short: 'routes to', sentence: 'Traffic it receives goes on to the next step.' }
    case 'TRIGGERS':
      return { short: 'triggers', sentence: 'It starts the next step with what it receives.' }
    case 'RUNS_AS':
      return { short: 'runs as', sentence: "It runs with this role's permissions." }
    case 'CAN_ASSUME':
      return { short: 'can assume', sentence: 'It may assume the next role.' }
    case 'ACCESSES': {
      const level = LEVEL[String(a.level)] ?? LEVEL.read!
      return { short: level.short, sentence: `Its policies allow ${level.word} access to the next step.` }
    }
    case 'IS_ADMIN':
      return { short: 'is administrator', sentence: 'Its policies allow every action on every resource.' }
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
      return e.target_uid === 'any:ssm'
        ? { short: 'can run commands through', sentence: 'It may send commands or start sessions through Systems Manager.' }
        : { short: 'runs commands on', sentence: 'Systems Manager manages this instance and reaches it.' }
    case 'MEMBER_OF':
      return /:iam::\d{12}:group\//.test(e.target_uid)
        ? { short: 'is in', sentence: 'It is a member of this group.' }
        : { short: 'is in', sentence: 'It is in this security group.' }
    case 'ALLOWS_INGRESS':
      return { short: 'admits', sentence: 'This security group admits the traffic.' }
  }
  const words = e.type.toLowerCase().replace(/_/g, ' ')
  return { short: words, sentence: `${words.charAt(0).toUpperCase()}${words.slice(1)}.` }
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
const OUTSIDER_KIND: Record<string, string> = {
  other_account: 'Another account',
  anyone: 'Anyone',
  oidc_no_subject: 'An OpenID Connect provider with no subject condition',
}
const AUTH: Record<string, string> = { NONE: 'None', AWS_IAM: 'IAM' }
const FAMILY: Record<string, string> = { ipv4: 'IPv4', ipv6: 'IPv6' }
// How the internet reaches a door (`via`, written by the internet rules).
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
const DOOR_BLOCK = new Set(['network', 'reason', 'sources', 'missing', 'listens', 'default_routes', 'state', 'actions'])
// Ports, once: CloudFox's port and ports, the rules' open and open_ports, lateral ports.
const PORT_KEYS = new Set(['ports', 'port', 'open', 'open_ports', 'protocol'])
const joined = (values: string[]): string => values.join(', ')

/** The keys of a trust condition, never its values: "StringEquals sts:ExternalId". */
function conditionWords(v: unknown): string {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return 'None'
  const keys = Object.entries(v as Record<string, unknown>).flatMap(([op, inner]) =>
    inner && typeof inner === 'object' && !Array.isArray(inner) ? Object.keys(inner).map((k) => `${op} ${k}`) : [op],
  )
  return keys.length ? joined(keys) : 'None'
}

function raw(v: unknown): string {
  return typeof v === 'string' ? v : JSON.stringify(v)
}

/** An edge's facts in words (E12, Facts in words); a key the screen does not name is shown as
 * it is, in mono. */
export function factsOf(e: ChainEdge): Fact[] {
  const a = e.attributes
  const fromInternet = e.source_uid === INTERNET
  const facts: Fact[] = []
  const ports = fromInternet ? doorPorts(e) : (Array.isArray(a.ports) ? a.ports : []).map((p) => (typeof p === 'number' ? `tcp/${p}` : String(p)))
  if (ports.length) facts.push({ label: 'Ports', value: joined(ports.map(portLabel)), mono: true })
  for (const [key, value] of Object.entries(a)) {
    if (PORT_KEYS.has(key) || (fromInternet && DOOR_BLOCK.has(key))) continue
    const values = strings(value)
    switch (key) {
      case 'services':
        facts.push({ label: 'Services', value: joined(values.map(serviceName)) })
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
      case 'origin_id':
        facts.push({ label: 'Origin', value: raw(value), mono: true })
        break
      case 'access_keys':
        facts.push({ label: 'Active access keys', value: raw(value), mono: true })
        break
      case 'oldest_key_created':
        facts.push({ label: 'Oldest key created', value: raw(value).slice(0, 10), mono: true })
        break
      case 'kind':
        facts.push(e.type === 'OUTSIDER' ? { label: 'Outsider', value: OUTSIDER_KIND[String(value)] ?? raw(value) } : { label: key, value: raw(value), mono: true })
        break
      case 'account':
        facts.push({ label: 'Account', value: raw(value), mono: true })
        break
      case 'condition':
        facts.push({ label: 'Trust conditions', value: conditionWords(value), mono: true })
        break
      case 'external_id':
        if (value) facts.push({ label: 'External id', value: 'Required' })
        break
      case 'imds':
        facts.push({ label: 'Instance metadata', value: IMDS[String(value)] ?? raw(value) })
        break
      case 'ping_status':
        facts.push({ label: 'Systems Manager agent', value: raw(value) })
        break
      case 'module':
        facts.push({ label: 'CloudFox module', value: raw(value), mono: true })
        break
      case 'unevaluated':
        facts.push({ label: 'Not evaluated', value: joined(values.map((u) => UNEVALUATED[u] ?? u)) })
        break
      case 'checked':
        facts.push({ label: 'Argus checked', value: joined(values.map((c) => CHECKED[c] ?? c)) })
        break
      case 'auth_type':
        facts.push({ label: 'Authentication', value: AUTH[String(value)] ?? raw(value) })
        break
      case 'waf':
        facts.push({ label: 'WAF', value: value === true ? 'A web ACL protects it' : 'None' })
        break
      case 'families':
        facts.push({ label: 'Reached over', value: joined(values.map((f) => FAMILY[f] ?? f)) })
        break
      default:
        facts.push({ label: key, value: raw(value), mono: true })
    }
  }
  return facts
}

/** A step's type label and name (E12, Steps that are not a resource). `inbound` is the edge
 * that reaches the step, if any. */
export function stepLabel(node: Pick<MapNode, 'uid' | 'kind' | 'name' | 'type' | 'resource_id'>, inbound: StepEdge | null): { type: string; name: string } {
  if (node.kind === 'internet') return { type: 'Entry point', name: 'Internet' }
  if (node.kind === 'admin') return { type: 'Administrator', name: nodeName(node) }
  if (node.uid === 'any:ssm') return { type: 'Systems Manager', name: 'Instances it manages' }
  if (node.kind === 'any') return { type: 'Wildcard grant (*)', name: nodeName(node) }
  if (node.kind === 'external') return { type: 'Not in the inventory', name: nodeName(node) }
  if (inbound?.type === 'OUTSIDER') return { type: 'Outside the account', name: outsiderName(node.uid) }
  if (node.resource_id == null) return { type: 'Not in the inventory', name: node.name || uidTail(node.uid) }
  return { type: typeLabel(node.type), name: nodeName(node) }
}

/** The entry's metadata service, when its first step says a foothold reads its credentials. */
export const imdsV1 = (first: StepEdge | null | undefined): boolean => first?.attributes.imds === 'v1'
