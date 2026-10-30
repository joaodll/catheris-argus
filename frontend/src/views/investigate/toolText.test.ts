import { describe, expect, it } from 'vitest'
import { codeBody, toolText } from './toolText'

describe('tool text', () => {
  it('keeps bold, italic and code marks and nothing else', () => {
    expect(toolText('Enable **Block Public Access** with `ignore_public_acls`, *if needed*.')).toEqual([
      { kind: 'text', value: 'Enable ' },
      { kind: 'strong', value: 'Block Public Access' },
      { kind: 'text', value: ' with ' },
      { kind: 'code', value: 'ignore_public_acls' },
      { kind: 'text', value: ', ' },
      { kind: 'em', value: 'if needed' },
      { kind: 'text', value: '.' },
    ])
  })

  it('leaves markup as plain text', () => {
    expect(toolText('<img src=x onerror=alert(1)>')).toEqual([{ kind: 'text', value: '<img src=x onerror=alert(1)>' }])
  })

  it('takes a code snippet out of its fence', () => {
    expect(codeBody('```yaml\nResources:\n  B: 1\n```')).toEqual({ lang: 'yaml', body: 'Resources:\n  B: 1' })
    expect(codeBody('aws s3api get-bucket-acl --bucket b')).toEqual({ lang: null, body: 'aws s3api get-bucket-acl --bucket b' })
  })
})
