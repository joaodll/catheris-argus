/**
 * A resource type's glyph (ADR-0051; spec in the palace, frontend/f3152e04): about 30 named
 * types have their own, every other type its category's (assetTypes.categoryOf). One colour:
 * the glyph tells types apart at a glance, and the text beside it always names the type.
 */
import type { IconName } from '@/components/icons'
import { categoryOf } from '@/views/overview/assetTypes'

// The first pattern that matches wins, so a narrower one comes before its family's.
const NAMED: [RegExp, IconName][] = [
  [/^aws_ec2_instance$/, 'server'],
  [/^aws_lambda_function$/, 'lambda'],
  [/^aws_ecs_/, 'container'],
  [/^aws_eks_/, 'helm'],
  [/^aws_ecr(public)?_/, 'registry'],
  [/^aws_s3_bucket$/, 'bucket'],
  [/^aws_ebs_/, 'disk'],
  [/^aws_rds_db_/, 'database'],
  [/^aws_dynamodb_table$/, 'table'],
  [/^aws_vpc$/, 'vpc'],
  [/^aws_vpc_subnet$/, 'subnet'],
  [/^aws_vpc_security_group/, 'firewall'],
  [/^aws_ec2_.*load_balancer/, 'balancer'],
  [/^aws_ec2_target_group$/, 'target'],
  [/^aws_api_gateway/, 'gateway'],
  [/^aws_cloudfront_distribution$/, 'cdn'],
  [/^aws_route53_/, 'dns'],
  [/^aws_ec2_network_interface$/, 'plug'],
  [/^aws_iam_role$/, 'role'],
  [/^aws_iam_user$/, 'user'],
  [/^aws_iam_group$/, 'users'],
  [/^aws_iam_policy/, 'policy'],
  [/^aws_iam_access_key$/, 'key'],
  [/^aws_kms_key$/, 'kms'],
  [/^aws_secretsmanager_secret$/, 'lock'],
  [/^aws_wafv2_web_acl$/, 'filter'],
  [/^aws_acm_certificate$/, 'certificate'],
  [/^aws_sqs_queue$/, 'queue'],
  [/^aws_sns_topic$/, 'topic'],
  [/^aws_eventbridge_/, 'event'],
  [/^aws_scheduler_schedule$/, 'clock'],
  [/^aws_(sfn_state_machine|pipes_pipe)$/, 'flow'],
  [/^aws_kinesis_/, 'stream'],
  [/^aws_cloudwatch_log_group$/, 'log'],
  [/^aws_cloudformation_stack$/, 'stack'],
]

const BY_CATEGORY: Record<string, IconName> = {
  Compute: 'chip',
  Containers: 'container',
  Storage: 'disk',
  Database: 'database',
  Network: 'nodes',
  Identity: 'key',
  Security: 'shield',
  Analytics: 'chart',
  Integration: 'flow',
  Management: 'sliders',
  Other: 'cube',
}

/** The glyph for a resource type; a resource Argus has no type for is a plain cube. */
export function resourceGlyph(type: string | null): IconName {
  if (!type) return 'cube'
  for (const [pattern, glyph] of NAMED) if (pattern.test(type)) return glyph
  return BY_CATEGORY[categoryOf(type)] ?? 'cube'
}
