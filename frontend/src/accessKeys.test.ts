import { describe, expect, it } from 'vitest'
import { accessKeyBody, isTemporaryKey } from './accessKeys'

// Fake ids only, built at runtime so no scanner mistakes them for credentials.
const LONG_LIVED = 'AKIA' + 'X'.repeat(16)
const TEMPORARY = 'ASIA' + 'X'.repeat(16)

describe('access keys', () => {
  it('knows a temporary key by its prefix', () => {
    expect(isTemporaryKey(TEMPORARY)).toBe(true)
    expect(isTemporaryKey(` ${TEMPORARY.toLowerCase()}`)).toBe(true)
    expect(isTemporaryKey(LONG_LIVED)).toBe(false)
    expect(isTemporaryKey('')).toBe(false)
  })

  it('sends the session token with a temporary key only', () => {
    const typed = { secret: 'fake-secret', sessionToken: 'fake-token' }
    expect(accessKeyBody({ accessKeyId: TEMPORARY, ...typed }).session_token).toBe('fake-token')
    expect(accessKeyBody({ accessKeyId: LONG_LIVED, ...typed }).session_token).toBeNull()
    expect(accessKeyBody({ accessKeyId: TEMPORARY, secret: 'x', sessionToken: '' }).session_token).toBeNull()
  })
})
