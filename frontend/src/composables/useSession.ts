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

export async function refreshSession(): Promise<boolean> {
  try {
    const { data, response } = await api.GET('/api/v1/auth/session')
    session.value = response.ok && data ? data : null
  } catch {
    session.value = null
  }
  return session.value !== null
}

export async function signOut(): Promise<void> {
  try {
    await api.POST('/api/v1/auth/sign-out')
  } finally {
    session.value = null
  }
}
