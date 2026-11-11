import { describe, expect, it } from 'vitest'
import { byProvider, CATEGORIES, categoryOf, groupTypes } from './assetTypes'

describe('categoryOf', () => {
  it('places a type by its service, and EC2 by what it is', () => {
    const cases: [string, string][] = [
      ['aws_ec2_instance', 'Compute'],
      ['aws_ec2_launch_template', 'Compute'],
      ['aws_lambda_function', 'Compute'],
      ['aws_eks_cluster', 'Containers'],
      ['aws_ecr_repository', 'Containers'],
      ['aws_s3_bucket', 'Storage'],
      ['aws_ebs_volume', 'Storage'],
      ['aws_rds_db_instance', 'Database'],
      ['aws_dynamodb_table', 'Database'],
      ['aws_ec2_application_load_balancer', 'Network'],
      ['aws_ec2_network_interface', 'Network'],
      ['aws_vpc_security_group', 'Network'],
      ['aws_api_gatewayv2_api', 'Network'],
      ['aws_iam_role', 'Identity'],
      ['aws_kms_key', 'Security'],
      ['aws_wafv2_web_acl', 'Security'],
      ['aws_glue_job', 'Analytics'],
      ['aws_bedrock_agent', 'Analytics'],
      ['aws_sqs_queue', 'Integration'],
      ['aws_cloudtrail_trail', 'Management'],
      ['aws_codebuild_project', 'Management'],
      ['aws_iot_thing', 'Other'],
      ['aws_something_new', 'Other'],
    ]
    expect(cases.map(([type]) => [type, categoryOf(type)])).toEqual(cases)
  })

  it('has eleven categories, Other last', () => {
    expect(CATEGORIES).toEqual(['Compute', 'Containers', 'Storage', 'Database', 'Network', 'Identity', 'Security', 'Analytics', 'Integration', 'Management', 'Other'])
  })
})

describe('groupTypes', () => {
  it('sums each category in the fixed order, one colour for all and Other muted', () => {
    const groups = groupTypes([
      { type: 'aws_ec2_instance', count: 66 },
      { type: 'aws_iam_role', count: 65 },
      { type: 'aws_s3_bucket', count: 40 },
      { type: 'aws_lambda_function', count: 40 },
      { type: 'aws_vpc_security_group', count: 28 },
      { type: 'aws_ec2_application_load_balancer', count: 5 },
      { type: 'aws_rds_db_instance', count: 3 },
      { type: 'aws_something_new', count: 2 },
    ])
    expect(groups.map((g) => [g.name, g.count, g.color])).toEqual([
      ['Compute', 106, 'var(--tool-steampipe)'],
      ['Storage', 40, 'var(--tool-steampipe)'],
      ['Database', 3, 'var(--tool-steampipe)'],
      ['Network', 33, 'var(--tool-steampipe)'],
      ['Identity', 65, 'var(--tool-steampipe)'],
      ['Other', 2, 'var(--muted)'],
    ])
    expect(groups.find((g) => g.name === 'Network')?.types).toEqual(['aws_vpc_security_group', 'aws_ec2_application_load_balancer'])
  })
})

describe('byProvider', () => {
  const coverage = { aws: 'covered', gcp: 'not covered', oci: 'not covered' }

  it('splits types by provider prefix, largest category first and Other last', () => {
    const [aws, gcp, oci] = byProvider(
      [
        { type: 'aws_ec2_instance', count: 10 },
        { type: 'aws_something_new', count: 50 },
        { type: 'aws_iam_role', count: 30 },
        { type: 'aws_s3_bucket', count: 5 },
      ],
      coverage,
    )
    expect(aws?.groups.map((g) => [g.name, g.count])).toEqual([
      ['Identity', 30],
      ['Compute', 10],
      ['Storage', 5],
      ['Other', 50],
    ])
    expect(aws?.total).toBe(95)
    expect(aws?.covered).toBe(true)
    expect([gcp?.covered, gcp?.total, oci?.covered, oci?.total]).toEqual([false, null, false, null])
  })

  it('leaves a covered provider without a scan at null, never 0', () => {
    expect(byProvider([], coverage)[0]).toMatchObject({ id: 'aws', covered: true, total: null, groups: [] })
  })
})
