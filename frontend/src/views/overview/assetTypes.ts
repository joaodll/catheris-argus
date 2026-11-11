/**
 * Assets by category (round 5, 2026-11-10; spec in the palace, frontend/1d636dd5): the one
 * taxonomy the Overview's Inventory card and the Resources Summary share.
 */

import { PROVIDERS } from '@/providers'

export interface TypeGroup {
  name: string
  color: string
  count: number
  types: string[]
}

export const OTHER = 'Other'
// One colour for every category (owner, 2026-11-10, decisions/1bdf306b): a category's bar is one
// measure, its asset count, so length carries it and the name tells categories apart. The
// inventory is Steampipe's, so its fixed tool colour, as the Summary's other inventory bars.
// Other is the rest, in the muted grey.
const CATEGORY_COLOR = 'var(--tool-steampipe)'
const OTHER_COLOR = 'var(--muted)'

// By service (argus_v8: every configuration table is inventoried, so types are matched by
// their service segment, not listed one by one). Parts, settings and links are not assets
// and never reach these counts (the backend leaves them out of assets.by_type). A service
// listed nowhere falls into Other.
const service = (t: string) => t.split('_')[1] ?? ''
// EC2 holds both instances and their network: these are its compute types, the rest is Network.
const isEc2Compute = (t: string) => /^aws_ec2_(instance|ami|autoscaling|launch|fleet|spot|capacity|placement|key_pair)/.test(t)

const SERVICES: Record<string, string[]> = {
  Compute: ['lambda', 'batch', 'elastic', 'lightsail', 'app', 'appstream', 'workspaces', 'serverlessapplicationrepository', 'amplify'],
  Containers: ['ecs', 'eks', 'ecr', 'ecrpublic'],
  Storage: ['s3', 's3tables', 'ebs', 'efs', 'fsx', 'glacier', 'backup', 'dlm', 'drs', 'datasync', 'transfer', 'media'],
  Database: ['rds', 'dynamodb', 'docdb', 'neptune', 'dax', 'memorydb', 'elasticache', 'keyspaces', 'timestreamwrite', 'redshift', 'redshiftserverless', 'dms'],
  Network: ['vpc', 'ec2', 'route53', 'cloudfront', 'api', 'globalaccelerator', 'directconnect', 'service'],
  Identity: ['iam', 'identitystore', 'ssoadmin', 'cognito', 'rolesanywhere', 'organizations', 'directory', 'ram'],
  Security: [
    'kms', 'acm', 'acmpca', 'secretsmanager', 'accessanalyzer', 'guardduty', 'inspector', 'inspector2', 'macie2', 'securityhub',
    'securitylake', 'shield', 'waf', 'wafregional', 'wafv2', 'fms', 'networkfirewall', 'auditmanager',
  ],
  Analytics: [
    'athena', 'glue', 'lakeformation', 'emr', 'kinesis', 'kinesisanalyticsv2', 'msk', 'mskconnect', 'opensearch', 'elasticsearch',
    'cloudsearch', 'quicksight', 'sagemaker', 'bedrock',
  ],
  Integration: ['sns', 'sqs', 'eventbridge', 'pipes', 'scheduler', 'sfn', 'mq', 'appsync', 'ses', 'pinpoint'],
  Management: [
    'cloudformation', 'cloudtrail', 'cloudwatch', 'config', 'ssm', 'ssmincidents', 'servicecatalog', 'servicequotas', 'account', 'oam',
    'resource', 'region', 'synthetics', 'appconfig', 'mgn', 'codeartifact', 'codebuild', 'codecommit', 'codedeploy', 'codepipeline', 'codestar',
  ],
}
/** The categories in their fixed order, Other last. */
export const CATEGORIES = [...Object.keys(SERVICES), OTHER]
const CATEGORY_OF = new Map(Object.entries(SERVICES).flatMap(([name, services]) => services.map((s) => [s, name] as const)))

/** A type's category; EC2's compute types are Compute, its other types Network. */
export function categoryOf(type: string): string {
  if (isEc2Compute(type)) return 'Compute'
  return CATEGORY_OF.get(service(type)) ?? OTHER
}

/** The types grouped by category, in the fixed order, empty categories left out. */
export function groupTypes(byType: { type: string; count: number }[]): TypeGroup[] {
  const groups = new Map<string, TypeGroup>()
  for (const { type, count } of byType) {
    const name = categoryOf(type)
    const entry = groups.get(name) ?? { name, color: name === OTHER ? OTHER_COLOR : CATEGORY_COLOR, count: 0, types: [] }
    entry.count += count
    entry.types.push(type)
    groups.set(name, entry)
  }
  return CATEGORIES.map((name) => groups.get(name)).filter((g): g is TypeGroup => g !== undefined && g.count > 0)
}

/** Largest first, Other always last. */
export function bySize(groups: TypeGroup[]): TypeGroup[] {
  return [...groups].sort((a, b) => Number(a.name === OTHER) - Number(b.name === OTHER) || b.count - a.count)
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
    const groups = bySize(groupTypes(byType.filter((t) => t.type.startsWith(`${id}_`))))
    const total = groups.reduce((n, g) => n + g.count, 0)
    return { id, name, covered: coverage[id] === 'covered', total: groups.length ? total : null, groups }
  })
}
