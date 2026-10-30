import { describe, expect, it } from 'vitest'
import { isPathFiltered, parsePathFilters, parsePathId, parsePathOrder, pathApiFilters, pathFiltersToQuery, toggleDate } from './pathFilters'
import { confidenceLine } from './confidence'
import { breakLink, severityLine } from './pathText'
import { doorPorts, factsOf, moveWords, outsiderName, pathLine, stepLabel, wayIn, type ChainEdge } from './pathWords'
import { portLabel, sortPorts } from './ports'
import type { MapNode } from '../map/mapGraph'

describe('Attack paths filters in the URL', () => {
  it('round-trips the filters and leaves defaults out', () => {
    const query = {
      severity: ['critical', 'high'],
      category: 'IAM privilege escalation',
      kind: ['internet-exposed-admin-port', 'internet-to-admin'],
      confidence: ['candidate', 'confirmed'],
      connection: '3',
      state: 'resolved',
      through: 'arn:aws:iam::1:role/app',
    }
    const filters = parsePathFilters(query)
    expect(pathFiltersToQuery(filters)).toEqual({ ...query, category: ['IAM privilege escalation'] })
    expect(pathFiltersToQuery(parsePathFilters({}))).toEqual({
      severity: undefined,
      category: undefined,
      kind: undefined,
      confidence: undefined,
      connection: undefined,
      state: undefined,
      through: undefined,
    })
    expect(isPathFiltered(parsePathFilters({}))).toBe(false)
    expect(isPathFiltered(filters)).toBe(true)
  })

  it('ignores what it does not know', () => {
    const f = parsePathFilters({ severity: ['urgent', 'low'], kind: ['Internet To Admin', 'a; DROP', 'internet-to-data'], confidence: ['sure', 'unknown'], rule: 'internet-chain-to-admin', connection: 'x', state: 'gone', through: 'u'.repeat(3000) })
    expect(f).toMatchObject({ severity: ['low'], kind: ['internet-to-data'], confidence: ['unknown'], connection: null, state: 'open', through: null })
    expect(pathFiltersToQuery(f)).not.toHaveProperty('rule') // links from before 2026-10-10
    expect(parsePathOrder({ order: 'rule_id' })).toBe('severity')
    expect(parsePathId({ path: '0' })).toBeNull()
    expect(parsePathId({ path: '12' })).toBe(12)
  })

  it('builds the API parameters and toggles the date order', () => {
    expect(pathApiFilters(parsePathFilters({ confidence: 'supported', connection: '2', kind: 'internet-exposed' }))).toEqual({
      severity: [],
      category: [],
      kind: ['internet-exposed'],
      confidence: ['supported'],
      connection_id: 2,
      state: 'open',
      through: null,
    })
    expect(toggleDate('severity', 'last_seen')).toBe('last_seen_desc')
    expect(toggleDate('last_seen_desc', 'last_seen')).toBe('last_seen_asc')
  })
})

describe('Attack paths wording', () => {
  it.each([
    ['INTERNET_REACHABLE', 'internet', 'x', {}, 'Remove public access'],
    ['ROUTES_TO', 'internet', 'x', {}, 'Remove public access'],
    ['ROUTES_TO', 'internet', 'x', { via: 'resource_policy' }, 'Remove the statement for "*"'],
    ['PUBLIC_UNVERIFIED', 'internet', 'x', {}, 'Let Argus read what is missing'],
    ['PUBLIC_RESTRICTED', 'internet', 'x', { reason: 'not_running' }, 'Already closed. Keep the control that closes it, and close what its security groups open'],
    ['PUBLIC_RESTRICTED', 'internet', 'x', { reason: 'block_public_access', via: 'resource_policy' }, 'Already closed by Block Public Access. Keep it on'],
    ['PUBLIC_RESTRICTED', 'internet', 'x', { reason: 'iam_auth' }, 'Already closed by IAM authentication. Keep it on'],
    ['OUTSIDER', 'internet', 'x', {}, 'Remove the outside principal'],
    ['HAS_CREDENTIAL', 'internet', 'x', {}, "Replace the user's access keys"],
    ['ROUTES_TO', 'arn:a', 'arn:b', {}, 'Stop routing'],
    ['MEMBER_OF', 'arn:i', 'arn:aws:ec2:us-east-1:111122223333:security-group/sg-1', {}, 'Move the resource'],
    ['MEMBER_OF', 'arn:u', 'arn:aws:iam::111122223333:group/admins', {}, 'Review whether'],
    ['CAN_PRIVESC_TO', 'a', 'b', {}, 'Remove the permissions'],
    ['CAN_ESCALATE_TO', 'a', 'b', {}, 'Remove the permissions named here'],
    ['CAN_CONNECT_TO', 'a', 'b', {}, 'Admit this port only'],
    ['CAN_RUN_ON', 'a', 'any:ssm', {}, 'Limit ssm:SendCommand'],
    ['ACCESSES', 'a', 'b', {}, 'Grant only the data access'],
    ['HAS_POLICY', 'a', 'b', {}, 'Review whether'],
  ])('says how to break %s', (type, source, target, attributes, start) => {
    expect(breakLink({ type, source_uid: source, target_uid: target, attributes }).startsWith(start)).toBe(true)
  })

  it('explains the severity', () => {
    expect(severityLine({ severity: 'critical', base_severity: 'high', entry_confirmed: true, has_failing: true })).toBe(
      'High for its kind, raised to Critical: Argus confirmed the internet reaches the entry.',
    )
    expect(severityLine({ severity: 'low', base_severity: 'medium', entry_confirmed: false, has_failing: false })).toBe(
      'Medium for its kind, lowered to Low: no resource on the path has a failing finding.',
    )
    expect(severityLine({ severity: 'high', base_severity: 'high', entry_confirmed: false, has_failing: true })).toBe('High for its kind.')
    expect(severityLine({ severity: 'high', base_severity: null, entry_confirmed: null, has_failing: null })).toBeNull()
  })


  it('says how sure a path is', () => {
    expect(confidenceLine('supported')).toMatch(/^Supported, its weakest step\. The configuration is there/)
    expect(confidenceLine(null)).toBeNull()
  })
})

const edge = (type: string, attributes: Record<string, unknown> = {}, from = 'internet', to = 'arn:aws:ec2:us-east-1:111122223333:instance/i-1', origin = 'rule:internet-entry@8'): ChainEdge => ({
  type,
  origin,
  source_uid: from,
  target_uid: to,
  attributes,
})

describe('Attack paths: how a path gets in (the path line)', () => {
  it('names ports', () => {
    expect(portLabel('tcp/22')).toBe('tcp/22 (SSH)')
    expect(portLabel('6/3389')).toBe('6/3389 (RDP)')
    expect(portLabel('udp/53')).toBe('udp/53 (DNS)')
    expect(portLabel('udp/22')).toBe('udp/22')
    expect(portLabel('tcp/8000-8100')).toBe('tcp/8000-8100')
    expect(portLabel('tcp/9999')).toBe('tcp/9999')
    expect(portLabel('all')).toBe('all ports')
    expect(portLabel('icmp')).toBe('icmp')
    expect(sortPorts(['tcp/443', 'udp/53', 'tcp/80', 'all', 'tcp/22', 'tcp/80'])).toEqual(['all', 'tcp/22', 'tcp/80', 'tcp/443', 'udp/53'])
  })

  it('reads a door as the path kinds do', () => {
    expect(doorPorts(edge('ROUTES_TO', { open: ['tcp/3389', 'tcp/22'] }))).toEqual(['tcp/22', 'tcp/3389'])
    const network = [{ open: { ipv4: ['tcp/22'], ipv6: ['tcp/5432'] } }]
    expect(doorPorts(edge('PUBLIC_RESTRICTED', { open_ports: ['tcp/22'], network }))).toEqual(['tcp/22', 'tcp/5432'])
    expect(doorPorts(edge('PUBLIC_UNVERIFIED', { open_ports: ['tcp/80'], network }))).toEqual(['tcp/22', 'tcp/5432'])
    expect(doorPorts(edge('INTERNET_REACHABLE', { ports: '80, 443,8000-8100,x' }, 'internet', 'h', 'cloudfox'))).toEqual(['tcp/80', 'tcp/443', 'tcp/8000-8100'])
    expect(doorPorts(edge('INTERNET_REACHABLE', { port: 53, protocol: 'UDP' }, 'internet', 'h', 'cloudfox'))).toEqual(['udp/53'])
    // A CloudFox ROUTES_TO from the internet is not Argus's verdict (doors.py).
    expect(doorPorts(edge('ROUTES_TO', { open: ['tcp/22'] }, 'internet', 'h', 'cloudfox'))).toEqual([])
  })

  it.each([
    [edge('ROUTES_TO', { open: ['tcp/22', 'tcp/3389'] }), 'Exposed: tcp/22 (SSH), tcp/3389 (RDP)'],
    [edge('ROUTES_TO', { open: ['tcp/21', 'tcp/22', 'tcp/23', 'tcp/3389'] }), 'Exposed: tcp/21 (FTP), tcp/22 (SSH), tcp/23 (Telnet) and 1 more'],
    [edge('ROUTES_TO', {}), 'Exposed'],
    [edge('INTERNET_REACHABLE', { port: '443' }, 'internet', 'h', 'cloudfox'), 'Exposed: tcp/443 (HTTPS)'],
    [edge('PUBLIC_UNVERIFIED', { network: [{ open: { ipv4: ['tcp/22'], ipv6: [] } }] }), 'Reach unknown: tcp/22 (SSH)'],
    [edge('PUBLIC_RESTRICTED', { reason: 'not_running', open_ports: ['tcp/22'] }), 'Restricted (not running): tcp/22 (SSH)'],
    [edge('PUBLIC_RESTRICTED', { reason: 'block_public_access', via: 'resource_policy' }), 'Restricted (Block Public Access)'],
    [edge('ROUTES_TO', { via: 'resource_policy', actions: ['sqs:sendmessage'] }), 'Public by its policy: anyone may sqs:sendmessage'],
    [edge('OUTSIDER', { kind: 'other_account', account: '210987654321' }), 'Outsider: account 210987654321'],
    [edge('OUTSIDER', { kind: 'anyone' }), 'Outsider: anyone'],
    [edge('OUTSIDER', { kind: 'oidc_no_subject' }), 'Outsider: any token from its OpenID Connect provider'],
    [edge('HAS_CREDENTIAL', { credentials: ['access_key'] }), 'Leaked credential: access key'],
    [edge('HAS_CREDENTIAL', { credentials: ['access_key', 'console_password_no_mfa'] }), 'Leaked credential: access key or console password without MFA'],
    [edge('ROUTES_TO', { open: ['tcp/22'] }, 'internet', 'h', 'manual'), null],
  ])('says how it gets in (%#)', (step, expected) => {
    expect(wayIn(step)).toBe(expected)
  })

  it('joins how it gets in with where it goes', () => {
    const door = 'arn:aws:ec2:us-east-1:111122223333:instance/i-1'
    const base = { entry_uid: door, target_uid: door, entry_name: 'bastion-1', target_name: 'bastion-1', node_uids: ['internet', door] }
    expect(pathLine({ ...base, entry_step: edge('ROUTES_TO', { open: ['tcp/22'] }) })).toBe('Exposed: tcp/22 (SSH) · bastion-1')
    const chain = { ...base, target_uid: 'admin:111122223333', target_name: null, node_uids: ['internet', door, 'r', 'admin:111122223333'] }
    expect(pathLine({ ...chain, entry_step: edge('ROUTES_TO', { open: ['tcp/443'] }) })).toBe('Exposed: tcp/443 (HTTPS) · bastion-1 → … → Admin · 111122223333 · 3 steps')
    // A path listed without its first step keeps the line from before.
    expect(pathLine({ ...base, entry_step: null })).toBe('bastion-1 → … → bastion-1 · 1 step')
    const outside = { ...chain, entry_uid: 'arn:aws:iam::210987654321:root', entry_name: null, entry_step: edge('OUTSIDER', { kind: 'other_account', account: '210987654321' }) }
    expect(pathLine(outside)).toBe('Outsider: account 210987654321 · Account 210987654321 → … → Admin · 111122223333 · 3 steps')
  })

  it('names an outsider', () => {
    expect(outsiderName('*')).toBe('Anyone')
    expect(outsiderName('arn:aws:iam::210987654321:root')).toBe('Account 210987654321')
    expect(outsiderName('210987654321')).toBe('Account 210987654321')
    expect(outsiderName('arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com')).toBe('token.actions.githubusercontent.com')
    expect(outsiderName('arn:aws:iam::210987654321:role/deployer')).toBe('deployer')
  })
})

describe('Attack paths: moves in words', () => {
  it.each([
    [edge('ROUTES_TO', { open: ['tcp/22'] }), 'reaches it on tcp/22 (SSH)', 'The internet reaches it on tcp/22 (SSH).'],
    [edge('ROUTES_TO', { via: 'resource_policy', actions: ['s3:getobject'] }), 'anyone may s3:getobject', 'Its own policy lets anyone s3:getobject.'],
    [edge('PUBLIC_RESTRICTED', { reason: 'nacl_blocks' }), 'kept out: network ACL', 'Argus found it closed to the internet: one change would open this path.'],
    [edge('HAS_CREDENTIAL', { credentials: ['console_password_no_mfa'] }), 'with a leaked console password', "Whoever holds this user's console password without MFA acts as the user."],
    [edge('CAN_ESCALATE_TO', { methods: ['iam:createpolicyversion', 'iam:passrole+ec2:runinstances'] }, 'arn:r', 'admin:1'), 'can escalate via iam:CreatePolicyVersion and 1 more', 'It can make itself an administrator: its policies allow iam:CreatePolicyVersion, iam:PassRole + ec2:RunInstances.'],
    [edge('CAN_CONNECT_TO', { ports: [22, 3389], services: ['rdp', 'ssh'] }, 'arn:a', 'arn:b'), 'can connect over RDP, SSH', 'From here an attacker can open RDP, SSH on the next step: its security groups admit tcp/22 (SSH), tcp/3389 (RDP) from a private range.'],
    [edge('CAN_RUN_ON', { via: ['ssm:sendcommand'] }, 'arn:r', 'any:ssm'), 'can run commands through', 'It may send commands or start sessions through Systems Manager.'],
    [edge('CAN_RUN_ON', { ping_status: 'Online' }, 'any:ssm', 'arn:i'), 'runs commands on', 'Systems Manager manages this instance and reaches it.'],
    [edge('ACCESSES', { level: 'full' }, 'arn:r', 'arn:b'), 'has full access to', 'Its policies allow full access to the next step.'],
    [edge('HAS_POLICY', {}, 'arn:r', 'arn:p'), 'has policy', 'Has policy.'],
  ])('words %#', (e, short, sentence) => {
    expect(moveWords(e)).toEqual({ short, sentence })
  })

  it('says the facts in words, never a trust condition value', () => {
    const facts = factsOf(edge('CAN_ASSUME', { condition: { StringEquals: { 'sts:ExternalId': 'not-shown' } }, unevaluated: ['conditions', 'scps'], extra: { a: 1 } }, 'arn:a', 'arn:b'))
    expect(facts).toEqual([
      { label: 'Trust conditions', value: 'StringEquals sts:ExternalId', mono: true },
      { label: 'Not evaluated', value: 'conditions, SCPs' },
      { label: 'extra', value: '{"a":1}', mono: true },
    ])
    expect(JSON.stringify(facts)).not.toContain('not-shown')
    const door = factsOf(edge('ROUTES_TO', { open: ['tcp/22'], imds: 'v1', network: [], state: 'running', checked: ['security_groups', 'network_acl'], via: 'public_ip' }))
    expect(door).toEqual([
      { label: 'Ports', value: 'tcp/22 (SSH)', mono: true },
      { label: 'Instance metadata', value: 'IMDSv1: no token required' },
      { label: 'Argus checked', value: 'security groups, network ACL' },
      { label: 'Reached through', value: 'a public address' },
    ])
  })

  it('names steps that are not a resource', () => {
    const node = (uid: string, kind: MapNode['kind'], resource_id: number | null = null) => ({ uid, kind, name: null, type: null, resource_id })
    expect(stepLabel(node('any:ssm', 'any'), null)).toEqual({ type: 'Systems Manager', name: 'Instances it manages' })
    expect(stepLabel(node('arn:aws:iam::210987654321:root', 'resource'), edge('OUTSIDER', { kind: 'other_account' }))).toEqual({ type: 'Outside the account', name: 'Account 210987654321' })
    expect(stepLabel(node('arn:aws:s3:::gone', 'resource'), null)).toEqual({ type: 'Not in the inventory', name: 'gone' })
    expect(stepLabel(node('internet', 'internet'), null)).toEqual({ type: 'Entry point', name: 'Internet' })
  })
})
