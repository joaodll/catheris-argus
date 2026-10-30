import { describe, expect, it } from 'vitest'
import type { DoorInterface } from './doorEvidence'
import { doorWhy } from './doorWhy'

const door = {
  reach: 'restricted' as const,
  reason: null as string | null,
  sources: [] as string[],
  missing: [] as string[],
  open: [] as string[],
  families: [] as string[],
  open_ports: [] as string[],
  listens: null as string[] | null,
  default_routes: [] as string[],
  network: [] as DoorInterface[],
  state: null as string | null,
  policy_actions: [] as string[],
}

describe('why a front door has its reach', () => {
  it('says what a resource public by its own policy lets anyone do, in each reach', () => {
    const queue = { ...door, policy_actions: ['sqs:sendmessage'] }
    expect(doorWhy({ ...queue, reach: 'open' })).toBe('Its policy lets anyone sqs:sendmessage')
    expect(doorWhy({ ...queue, reason: 'block_public_access', policy_actions: ['s3:getobject'] })).toBe(
      'Its policy lets anyone s3:getobject, but S3 Block Public Access keeps anonymous requests out',
    )
    expect(doorWhy({ ...queue, reach: 'unknown', missing: ['policy_condition:events'] })).toBe(
      'Its policy lets anyone sqs:sendmessage, under a condition Argus does not evaluate',
    )
    expect(doorWhy({ ...queue, reach: 'unknown', missing: ['s3_account_settings:123456789012'] })).toBe(
      "Argus can't tell: the account's S3 Block Public Access settings (123456789012) were not collected",
    )
  })

  it('says what a restricted door opens against what it serves', () => {
    expect(doorWhy({ ...door, reason: 'sg_no_public_source', open_ports: ['tcp/80'], listens: ['tcp/443'] })).toBe(
      'Security groups open tcp/80 to the internet, but it listens on tcp/443',
    )
    expect(doorWhy({ ...door, reason: 'sg_no_public_source', sources: ['203.0.113.0/24'] })).toBe('Security groups admit only: 203.0.113.0/24')
    expect(doorWhy({ ...door, reason: 'sg_no_public_source' })).toBe('No security group is open to the internet on a port it serves')
  })

  it('names where the default route goes when none reaches an internet gateway', () => {
    expect(doorWhy({ ...door, reason: 'no_internet_route', default_routes: ['nat-0a1b'] })).toBe(
      'No route to an internet gateway; the default route goes to nat-0a1b',
    )
    expect(doorWhy({ ...door, reason: 'no_internet_route', default_routes: ['none'] })).toBe(
      'No route to an internet gateway; there is no default route',
    )
  })

  it('names an instance one change away from the internet', () => {
    expect(doorWhy({ ...door, reason: 'no_public_address', open_ports: ['tcp/22'] })).toBe(
      'No public address, though its security groups open tcp/22 to the internet',
    )
    expect(doorWhy({ ...door, reason: 'nacl_blocks', open_ports: ['tcp/80'] })).toBe(
      'Security groups open tcp/80 to the internet; the network ACL blocks it',
    )
  })

  it('says a firewall endpoint route cannot be judged', () => {
    expect(doorWhy({ ...door, reach: 'unknown', missing: ['inspection_route:subnet-fw'] })).toBe(
      "Argus can't tell: subnet-fw routes the internet through a firewall endpoint, whose rules Argus does not read",
    )
    expect(doorWhy({ ...door, reach: 'unknown', missing: ['route_table:subnet-1'] })).toBe("Argus can't tell: route table for subnet-1 not collected")
  })

  // ADR-0035, fifth amendment: the evidence explains what the reason code alone could not.
  const iface = (over: Partial<DoorInterface>): DoorInterface => ({
    interface: 'eni-1',
    public: ['ipv4'],
    open: { ipv4: [], ipv6: [] },
    subnets: [{ subnet: 'subnet-1', family: 'ipv4', route: 'igw', acl: null }],
    ...over,
  })

  it('says a stopped instance is one start away', () => {
    expect(doorWhy({ ...door, reason: 'not_running', open_ports: ['tcp/22'], state: 'stopped' })).toBe(
      'Stopped, though its security groups open tcp/22 to the internet',
    )
  })

  it('names a rule open in a family the door has no address of', () => {
    const network = [iface({ open: { ipv4: [], ipv6: ['tcp/22'] } })]
    expect(doorWhy({ ...door, reason: 'sg_no_public_source', network })).toBe('Opens tcp/22 to ::/0 (IPv6); it has no public IPv6 address')
  })

  it('keeps the listener mismatch when the family it has is open too', () => {
    const network = [iface({ open: { ipv4: ['tcp/80'], ipv6: ['tcp/80'] } })]
    expect(doorWhy({ ...door, reason: 'sg_no_public_source', open_ports: ['tcp/80'], listens: ['tcp/443'], network })).toBe(
      'Security groups open tcp/80 to the internet, but it listens on tcp/443',
    )
  })

  it('says ICMP alone opens nothing that serves', () => {
    expect(doorWhy({ ...door, reason: 'sg_no_public_source', open_ports: ['icmp'], network: [iface({ open: { ipv4: ['icmp'], ipv6: [] } })] })).toBe(
      'Only icmp (ping) is open to the internet; no port that serves anything',
    )
  })

  it('names the private interface an open group sits on', () => {
    const network = [iface({ interface: 'eni-priv', public: [], open: { ipv4: ['tcp/22'], ipv6: [] } }), iface({ interface: 'eni-pub' })]
    expect(doorWhy({ ...door, reason: 'no_public_address', open_ports: ['tcp/22'], network })).toBe(
      'Its security groups open tcp/22 to the internet on eni-priv, which has no public address',
    )
  })

  it("lists an unknown door's open ports", () => {
    const network = [iface({ open: { ipv4: ['tcp/80'], ipv6: [] } })]
    expect(doorWhy({ ...door, reach: 'unknown', missing: ['inspection_route:subnet-fw'], network })).toBe(
      "Argus can't tell: subnet-fw routes the internet through a firewall endpoint, whose rules Argus does not read; its security groups open tcp/80",
    )
  })
})
