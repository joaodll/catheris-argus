import { describe, expect, it } from 'vitest'
import { byProvider, CATEGORIES, groupTypes } from './assetTypes'

describe('CATEGORIES', () => {
  it('has eleven categories in display order, Other last', () => {
    expect(CATEGORIES).toEqual(['Compute', 'Containers', 'Storage', 'Database', 'Network', 'Identity', 'Security', 'Analytics', 'Integration', 'Management', 'Other'])
  })
})

describe('groupTypes', () => {
  it('sums each category the API gives, in the display order, one colour for all and Other muted', () => {
    const groups = groupTypes([
      { type: 'aws_ec2_instance', count: 66, category: 'Compute' },
      { type: 'aws_iam_role', count: 65, category: 'Identity' },
      { type: 'aws_s3_bucket', count: 40, category: 'Storage' },
      { type: 'aws_lambda_function', count: 40, category: 'Compute' },
      { type: 'aws_vpc_security_group', count: 28, category: 'Network' },
      { type: 'aws_ec2_application_load_balancer', count: 5, category: 'Network' },
      { type: 'aws_rds_db_instance', count: 3, category: 'Database' },
      { type: 'aws_something_new', count: 2, category: 'Other' },
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
        { type: 'aws_ec2_instance', count: 10, category: 'Compute' },
        { type: 'aws_something_new', count: 50, category: 'Other' },
        { type: 'aws_iam_role', count: 30, category: 'Identity' },
        { type: 'aws_s3_bucket', count: 5, category: 'Storage' },
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
