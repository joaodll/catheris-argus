/** "Assets by type, per provider" (docs/ui/screens.md, "Inventory: assets by type, per provider"). */

import { PROVIDERS } from '@/providers'

export interface TypeGroup {
  name: string
  color: string
  count: number
  types: string[]
}

// By service (argus_v8: every configuration table is inventoried, so types are matched by
// their service segment, not listed one by one). Parts, settings and links are not assets
// and never reach this chart (the backend leaves them out of assets.by_type).
const service = (t: string) => t.split('_')[1] ?? ''
const COMPUTE = new Set(['lambda', 'ecs', 'eks', 'batch', 'emr', 'lightsail', 'app', 'elastic', 'sagemaker', 'appstream', 'workspaces'])
const IDENTITY = new Set(['iam', 'identitystore', 'ssoadmin', 'cognito', 'rolesanywhere', 'organizations', 'directory'])
const STORAGE = new Set([
  's3', 's3tables', 'rds', 'dynamodb', 'ebs', 'efs', 'fsx', 'backup', 'glacier', 'redshift', 'redshiftserverless',
  'elasticache', 'docdb', 'neptune', 'dax', 'memorydb', 'keyspaces', 'timestreamwrite', 'opensearch', 'elasticsearch',
  'ecr', 'ecrpublic', 'glue', 'athena', 'lakeformation', 'kinesis', 'msk', 'mskconnect',
])
const NETWORK = new Set([
  'vpc', 'route53', 'cloudfront', 'api', 'apigatewayv2', 'globalaccelerator', 'networkfirewall', 'directconnect',
  'waf', 'wafregional', 'wafv2', 'service', 'transfer',
])
const isEc2Compute = (t: string) => /^aws_ec2_(instance|ami|autoscaling|launch|fleet|spot|capacity|placement|key_pair)/.test(t)

const GROUPS: { name: string; color: string; match: (type: string) => boolean }[] = [
  { name: 'Compute', color: 'var(--type-compute)', match: (t) => COMPUTE.has(service(t)) || isEc2Compute(t) },
  { name: 'Identity', color: 'var(--type-identity)', match: (t) => IDENTITY.has(service(t)) },
  { name: 'Storage', color: 'var(--type-storage)', match: (t) => STORAGE.has(service(t)) },
  { name: 'Network', color: 'var(--type-network)', match: (t) => NETWORK.has(service(t)) || service(t) === 'ec2' },
]
const OTHER = { name: 'Other', color: 'var(--type-other)' }

/** A type's group (Compute, Identity, Storage, Network or Other) and its colour token: the same
 * colour means the same kind of resource on every screen (the Resource map's node borders). */
export function typeGroupOf(type: string): { name: string; color: string } {
  const group = GROUPS.find((g) => g.match(type)) ?? OTHER
  return { name: group.name, color: group.color }
}

export function groupTypes(byType: { type: string; count: number }[]): TypeGroup[] {
  const groups = new Map<string, TypeGroup>()
  for (const { type, count } of byType) {
    const group = typeGroupOf(type)
    const entry = groups.get(group.name) ?? { name: group.name, color: group.color, count: 0, types: [] }
    entry.count += count
    entry.types.push(type)
    groups.set(group.name, entry)
  }
  const order = [...GROUPS.map((g) => g.name), OTHER.name]
  return order.map((name) => groups.get(name)).filter((g): g is TypeGroup => g !== undefined && g.count > 0)
}

export interface ProviderInventory {
  id: string
  name: string
  covered: boolean
  /** null when the provider is covered but has no inventory scan yet. */
  total: number | null
  /** Largest first, Other always last. */
  groups: TypeGroup[]
}

/** Splits the Steampipe types by their provider prefix (aws_, gcp_, oci_), then groups each. */
export function byProvider(byType: { type: string; count: number }[], coverage: Record<string, string>): ProviderInventory[] {
  return PROVIDERS.map(({ id, name }) => {
    const groups = groupTypes(byType.filter((t) => t.type.startsWith(`${id}_`))).sort(
      (a, b) => Number(a.name === OTHER.name) - Number(b.name === OTHER.name) || b.count - a.count,
    )
    const total = groups.reduce((n, g) => n + g.count, 0)
    return { id, name, covered: coverage[id] === 'covered', total: groups.length ? total : null, groups }
  })
}
