/**
 * The password rules the API holds (ADR-0041: NIST SP 800-63B), checked before sending so the
 * user sees what is wrong under the field. The API checks again.
 */
export const MIN_PASSWORD = 12
export const MAX_PASSWORD = 256
export const PASSWORD_HELP = 'At least 12 characters. A long phrase is easier to remember than symbols.'

export type PasswordField = 'current' | 'new' | 'repeat'

/** What is wrong with a new password and its repetition, or null. */
export function newPasswordProblem(password: string, repeat: string, username: string): { field: PasswordField; message: string } | null {
  if (password.length < MIN_PASSWORD) return { field: 'new', message: `Use at least ${MIN_PASSWORD} characters.` }
  if (password.length > MAX_PASSWORD) return { field: 'new', message: `Use at most ${MAX_PASSWORD} characters.` }
  if (password.trim().toLowerCase() === username.toLowerCase()) return { field: 'new', message: "It can't be your username." }
  if (repeat !== password) return { field: 'repeat', message: "The passwords don't match." }
  return null
}

/** The field an API refusal names ("current_password: …", "new_password: …"), and its words. */
export function apiPasswordProblem(message: string): { field: PasswordField; message: string } {
  const [prefix, ...rest] = message.split(': ')
  const text = rest.join(': ')
  const sentence = text ? `${text.charAt(0).toUpperCase()}${text.slice(1)}.` : message
  if (prefix === 'current_password') return { field: 'current', message: sentence }
  if (prefix === 'new_password' || prefix === 'password') return { field: 'new', message: sentence }
  return { field: 'new', message }
}
