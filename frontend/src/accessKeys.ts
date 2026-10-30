/**
 * AWS access keys (ADR-0024): a long-lived key (AKIA...) alone, or a temporary
 * one (ASIA..., from SSO) that AWS accepts only with its session token.
 */

export interface AccessKeyInput {
  accessKeyId: string
  secret: string
  sessionToken: string
}

export function isTemporaryKey(accessKeyId: string): boolean {
  return accessKeyId.trim().toUpperCase().startsWith('ASIA')
}

/** The API's field names. A token typed for a key that turned out long-lived is not sent. */
export function accessKeyBody(key: AccessKeyInput): {
  access_key_id: string
  secret_access_key: string
  session_token: string | null
} {
  return {
    access_key_id: key.accessKeyId.trim(),
    secret_access_key: key.secret,
    session_token: isTemporaryKey(key.accessKeyId) && key.sessionToken ? key.sessionToken.trim() : null,
  }
}
