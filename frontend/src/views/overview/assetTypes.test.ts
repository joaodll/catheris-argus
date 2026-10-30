import { describe, expect, it } from 'vitest'
import { byProvider, groupTypes } from './assetTypes'

describe('groupTypes', () => {
  it('groups the live types into the five board groups, in order', () => {
    const groups = groupTypes([
      { type: 'aws_ec2_instance', count: 66 },
      { type: 'aws_iam_role', count: 65 },
      { type: 'aws_s3_bucket', count: 40 },
      { type: 'aws_lambda_function', count: 40 },
      { type: 'aws_vpc_security_group', count: 28 },
      { type: 'aws_ec2_application_load_balancer', count: 5 },
      { type: 'aws_something_new', count: 2 },
    ])
    expect(groups.map((g) => [g.name, g.count])).toEqual([
      ['Compute', 106],
      ['Identity', 65],
      ['Storage', 40],
      ['Network', 33],
      ['Other', 2],
    ])
  })
})

describe('groupTypes, every configuration table (argus_v8)', () => {
  it('places a type by its service', () => {
    const groups = groupTypes([
      { type: 'aws_ecs_cluster', count: 1 },
      { type: 'aws_ec2_launch_template', count: 1 },
      { type: 'aws_iam_policy', count: 1 },
      { type: 'aws_ebs_volume', count: 1 },
      { type: 'aws_cloudfront_distribution', count: 1 },
      { type: 'aws_ec2_network_interface', count: 1 },
      { type: 'aws_kms_key', count: 1 },
    ])
    expect(groups.map((g) => [g.name, g.types])).toEqual([
      ['Compute', ['aws_ecs_cluster', 'aws_ec2_launch_template']],
      ['Identity', ['aws_iam_policy']],
      ['Storage', ['aws_ebs_volume']],
      ['Network', ['aws_cloudfront_distribution', 'aws_ec2_network_interface']],
      ['Other', ['aws_kms_key']],
    ])
  })
})

describe('byProvider', () => {
  const coverage = { aws: 'covered', gcp: 'not covered', oci: 'not covered' }

  it('splits types by provider prefix, largest group first and Other last', () => {
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
