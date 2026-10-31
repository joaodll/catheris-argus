import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import SeverityTag from '@/components/SeverityTag.vue'
import { findingLine, originLabel, regionLabel, shortLink, typesByService, uidTail, webUrl } from './labels'

describe('investigate labels', () => {
  it('groups resource types by service for the type filter', () => {
    expect(typesByService(['aws_s3_bucket', 'aws_ec2_instance', 'aws_ec2_ami', 'aws_vpc'])).toEqual([
      { service: 'aws ec2', types: ['aws_ec2_ami', 'aws_ec2_instance'] },
      { service: 'aws s3', types: ['aws_s3_bucket'] },
      { service: 'aws vpc', types: ['aws_vpc'] },
    ])
  })

  it('shortens a uid to its last segment', () => {
    expect(uidTail('arn:aws:ec2:us-east-1:111111111111:instance/i-0abc')).toBe('i-0abc')
    expect(uidTail('arn:aws:s3:::my-bucket')).toBe('my-bucket')
    expect(uidTail('no-separator')).toBe('no-separator')
    expect(uidTail('ends-with/')).toBe('ends-with/')
  })

  it('names the global region and edge origins', () => {
    expect(regionLabel('global')).toBe('Global')
    expect(regionLabel('eu-west-1')).toBe('eu-west-1')
    expect(originLabel('rule:instance-role@1')).toBe('Rule')
    expect(originLabel('cloudfox')).toBe('CloudFox')
    expect(originLabel('manual')).toBe('Manual')
  })
})

describe('webUrl', () => {
  it('keeps web addresses and drops anything else', () => {
    expect(webUrl('https://hub.prowler.com/check/s3_bucket_public_access')).toBe('https://hub.prowler.com/check/s3_bucket_public_access')
    expect(webUrl('javascript:alert(1)')).toBeNull()
    expect(webUrl('not a url')).toBeNull()
    expect(webUrl(null)).toBeNull()
  })
})

describe('SeverityTag', () => {
  it('always carries the word, never colour alone', () => {
    expect(mount(SeverityTag, { props: { severity: 'critical' } }).text()).toBe('Critical')
    expect(mount(SeverityTag, { props: { severity: 'informational', compact: true } }).text()).toBe('Info')
  })
})

describe('Short links and finding lines (2026-10-31 review)', () => {
  it('shows a link as its site and the start of its path', () => {
    expect(shortLink('https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html')).toBe('docs.aws.amazon.com › lambda › latest › …')
    expect(shortLink('https://www.trendmicro.com/cloudoneconformity/')).toBe('trendmicro.com › cloudoneconformity')
    expect(shortLink('https://example.com')).toBe('example.com')
    expect(shortLink('https://example.com/a%20b/c')).toBe('example.com › a b › c')
    expect(shortLink('not a url')).toBe('not a url')
  })

  it("leads a Prowler row with its result, every other with its title", () => {
    const title = 'Ensure root account has a hardware MFA device enabled'
    const detail = 'Root account does not have a hardware MFA device enabled.'
    expect(findingLine({ tool: 'prowler', title, detail })).toEqual({ lead: detail, check: title })
    expect(findingLine({ tool: 'prowler', title, detail: '  ' })).toEqual({ lead: title, check: null })
    expect(findingLine({ tool: 'prowler', title, detail: null })).toEqual({ lead: title, check: null })
    expect(findingLine({ tool: 'cloudfox', title, detail })).toEqual({ lead: title, check: null })
  })
})
