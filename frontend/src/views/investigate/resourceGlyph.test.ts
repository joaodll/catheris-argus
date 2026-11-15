import { describe, expect, it } from 'vitest'
import { CATEGORIES } from '@/views/overview/assetTypes'
import { resourceGlyph } from './resourceGlyph'

describe("a resource type's glyph", () => {
  it('gives a named type its own', () => {
    expect(resourceGlyph('aws_ec2_instance')).toBe('server')
    expect(resourceGlyph('aws_lambda_function')).toBe('lambda')
    expect(resourceGlyph('aws_s3_bucket')).toBe('bucket')
    expect(resourceGlyph('aws_iam_role')).toBe('role')
    expect(resourceGlyph('aws_vpc_security_group')).toBe('firewall')
    expect(resourceGlyph('aws_ec2_application_load_balancer')).toBe('balancer')
    expect(resourceGlyph('aws_api_gatewayv2_api')).toBe('gateway')
  })

  it("keeps a narrower type apart from its family's", () => {
    expect(resourceGlyph('aws_vpc')).toBe('vpc')
    expect(resourceGlyph('aws_vpc_subnet')).toBe('subnet')
    expect(resourceGlyph('aws_vpc_route_table')).toBe('nodes') // no glyph of its own: Network
    expect(resourceGlyph('aws_ec2_target_group')).toBe('target')
  })

  it("falls back to the category's glyph, a different one for each", () => {
    const samples: Record<string, string> = {
      Compute: 'aws_ec2_ami',
      Containers: 'aws_ecs_cluster',
      Storage: 'aws_efs_file_system',
      Database: 'aws_redshift_cluster',
      Network: 'aws_vpc_route_table',
      Identity: 'aws_iam_server_certificate',
      Security: 'aws_guardduty_detector',
      Analytics: 'aws_glue_job',
      Integration: 'aws_mq_broker',
      Management: 'aws_ssm_document',
      Other: 'aws_unheard_of_thing',
    }
    expect(Object.keys(samples)).toEqual(CATEGORIES)
    const glyphs = Object.values(samples).map(resourceGlyph)
    expect(new Set(glyphs).size).toBe(CATEGORIES.length)
  })

  it('draws a cube for a resource with no type', () => {
    expect(resourceGlyph(null)).toBe('cube')
  })
})
