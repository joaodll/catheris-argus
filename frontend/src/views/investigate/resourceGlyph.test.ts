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
    expect(resourceGlyph('aws_vpc_route_table', 'Network')).toBe('nodes') // no glyph of its own: its category's
    expect(resourceGlyph('aws_ec2_target_group')).toBe('target')
  })

  it("falls back to the category the API gives, a different glyph for each", () => {
    const glyphs = CATEGORIES.map((category) => resourceGlyph('aws_unheard_of_thing', category))
    expect(new Set(glyphs).size).toBe(CATEGORIES.length)
  })

  it('draws a cube for a type without a named glyph or a known category', () => {
    expect(resourceGlyph('aws_unheard_of_thing')).toBe('cube')
    expect(resourceGlyph('aws_unheard_of_thing', 'Not a category')).toBe('cube')
  })

  it('draws a cube for a resource with no type', () => {
    expect(resourceGlyph(null)).toBe('cube')
  })
})
