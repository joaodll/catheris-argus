import { computed, ref } from 'vue'
import { api, type Schemas } from '@/api/client'

export type Role = Schemas['Session']['role']
const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }
export const ROLE_LABEL: Record<Role, string> = { viewer: 'Viewer', operator: 'Operator', admin: 'Admin' }

/** Who is signed in, their role, and whether they must choose a new password first (ADR-0041).
 * null: unknown or signed out. */
export const session = ref<Schemas['Session'] | null>(null)
export const username = computed(() => session.value?.username ?? null)

/** Whether the signed-in user's role reaches `needed`. A control the role cannot use is hidden
 * (docs/ui/screens.md, Roles on every screen); the API refuses it anyway. */
export function can(needed: Role): boolean {
  return session.value !== null && RANK[session.value.role] >= RANK[needed]
}

/** The session is over, however it ended. */
export function endSession(): void {
  session.value = null
}

/** Whether the last session check could not reach the API (nginx's 502 or 504, or no answer),
 * so Sign in can say so rather than look like a session that ended. */
export const apiUnreachable = ref(false)

export async function refreshSession(): Promise<boolean> {
  try {
    const { data, response } = await api.GET('/api/v1/auth/session')
    apiUnreachable.value = response.status === 502 || response.status === 504
    if (response.ok && data) session.value = data
    else endSession()
  } catch {
    apiUnreachable.value = true
    endSession()
  }
  return session.value !== null
}

export async function signOut(): Promise<void> {
  try {
    await api.POST('/api/v1/auth/sign-out')
  } finally {
    endSession()
  }
}
