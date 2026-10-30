/**
 * The typed API client. Types come from src/api/schema.d.ts, which is generated from
 * backend/openapi.json (`pnpm api:generate`); `pnpm api:check` fails when it is stale.
 *
 * Session: an HttpOnly cookie the app never sees. Writes carry the CSRF token: the readable
 * argus_csrf cookie, echoed in the X-Argus-CSRF header (double submit).
 */
import createClient, { type Middleware } from 'openapi-fetch'
import type { components, paths } from './schema'

export type Schemas = components['schemas']

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const SIGN_IN_PATH = '/api/v1/auth/sign-in'

export function readCookie(name: string, source: string = document.cookie): string | null {
  for (const part of source.split(';')) {
    const [key, ...rest] = part.trim().split('=')
    if (key === name) return decodeURIComponent(rest.join('='))
  }
  return null
}

export const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    if (!SAFE_METHODS.has(request.method)) {
      request.headers.set('X-Argus-CSRF', readCookie('argus_csrf') ?? '')
    }
    return request
  },
}

let onUnauthorized: () => void = () => {}
let onForbidden: () => void = () => {}

/** Called on any 401 except from sign-in itself: the session ended. */
export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler
}

/** Called on any 403: the role or the session's state may have changed since it was read. */
export function setForbiddenHandler(handler: () => void): void {
  onForbidden = handler
}

const sessionMiddleware: Middleware = {
  onResponse({ request, response }) {
    if (response.status === 401 && !new URL(request.url).pathname.startsWith(SIGN_IN_PATH)) {
      onUnauthorized()
    }
    if (response.status === 403) onForbidden()
    return response
  },
}

export const api = createClient<paths>({ baseUrl: window.location.origin, credentials: 'same-origin' })
api.use(csrfMiddleware, sessionMiddleware)

/** An API failure with the message to show the user (the API's own words when it gave any). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly detail: unknown = null,
  ) {
    super(message)
  }
}

interface ValidationItem {
  loc?: (string | number)[]
  msg?: string
}

export function messageOf(status: number, body: unknown): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  if (status === 403 && detail === 'your role does not allow this') {
    return 'Your role no longer allows this. Reload to see what you can do.'
  }
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length) {
    const first = detail[0] as ValidationItem
    const field = first.loc?.filter((p) => p !== 'body').join('.')
    // A model's own check ("Value error, bucket and region are set together") reads as a sentence.
    const msg = (first.msg ?? 'invalid value').replace(/^Value error, /, '')
    return field ? `${field}: ${msg}` : `${msg.charAt(0).toUpperCase()}${msg.slice(1)}.`
  }
  if (detail && typeof detail === 'object' && 'message' in detail) {
    return String((detail as { message: unknown }).message)
  }
  if (status >= 500) return 'Argus had a problem answering. Try again in a moment.'
  if (status === 0) return "Argus can't reach its API."
  return `The request failed (${status}).`
}

interface Result<T> {
  data?: T
  error?: unknown
  response: Response
}

/** Returns the data, or throws an ApiError carrying the user-facing message. */
export async function unwrap<T>(call: Promise<Result<T>>): Promise<T> {
  let result: Result<T>
  try {
    result = await call
  } catch {
    throw new ApiError(0, "Argus can't reach its API.")
  }
  if (!result.response.ok) {
    const detail = (result.error as { detail?: unknown } | undefined)?.detail ?? null
    throw new ApiError(result.response.status, messageOf(result.response.status, result.error), detail)
  }
  return result.data as T
}
