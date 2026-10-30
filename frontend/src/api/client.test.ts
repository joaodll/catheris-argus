import { describe, expect, it } from 'vitest'
import { csrfMiddleware, messageOf, readCookie } from './client'

describe('readCookie', () => {
  it('finds a cookie among others and decodes it', () => {
    expect(readCookie('argus_csrf', 'a=1; argus_csrf=x%2By; b=2')).toBe('x+y')
    expect(readCookie('missing', 'a=1')).toBeNull()
  })
})

describe('csrfMiddleware', () => {
  const run = (method: string) => {
    document.cookie = 'argus_csrf=token-123'
    const request = new Request('https://argus.test/api/v1/schedules', { method })
    const onRequest = csrfMiddleware.onRequest as (o: { request: Request }) => Request
    return onRequest({ request }).headers.get('X-Argus-CSRF')
  }

  it('adds the token to writes only', () => {
    expect(run('POST')).toBe('token-123')
    expect(run('DELETE')).toBe('token-123')
    expect(run('GET')).toBeNull()
  })
})

describe('messageOf', () => {
  it('uses the API message, a validation message, or a plain fallback', () => {
    expect(messageOf(422, { detail: 'role_arn must be an IAM role ARN' })).toBe(
      'role_arn must be an IAM role ARN',
    )
    expect(messageOf(422, { detail: [{ loc: ['body', 'seed'], msg: 'too large' }] })).toBe('seed: too large')
    expect(messageOf(409, { detail: { message: 'nothing queued: cooldown', refused: [] } })).toBe(
      'nothing queued: cooldown',
    )
    expect(messageOf(503, null)).toMatch(/problem/)
    // A model-level check has no field: its own words, as a sentence.
    expect(messageOf(422, { detail: [{ loc: ['body'], msg: 'Value error, bucket and region are set together' }] })).toBe(
      'Bucket and region are set together.',
    )
  })
})
