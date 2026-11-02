/**
 * The Resource map's "Recently opened" (round M3a; the spec is in the palace, frontend): the last
 * resources mapped in this tab, newest first, for the signed-in user only. A convenience, never a
 * record: any read or write survives storage being off, full or tampered with (the list is then
 * empty). Session storage, the owner's decision of 2026-11-02: resource names and ARNs go when the
 * tab closes, and the end of a session clears them, so they do not outlive it on a shared machine.
 */

export interface RecentResource {
  uid: string
  name: string | null
  type: string | null
  connectionId: number | null
  connectionName: string | null
}

export const RECENT_MAX = 8
const PREFIX = 'argus.map.recent'

function key(user: string): string {
  return `${PREFIX}:${user}`
}

const text = (v: unknown): v is string | null => v === null || typeof v === 'string'

function isRecent(v: unknown): v is RecentResource {
  if (typeof v !== 'object' || v === null) return false
  const r = v as Record<string, unknown>
  return (
    typeof r.uid === 'string' &&
    r.uid !== '' &&
    text(r.name) &&
    text(r.type) &&
    (r.connectionId === null || Number.isInteger(r.connectionId)) &&
    text(r.connectionName)
  )
}

/** This user's list; empty without a user, without storage, or when what is stored is not one. */
export function readRecent(user: string | null): RecentResource[] {
  if (!user) return []
  try {
    const raw = window.sessionStorage.getItem(key(user))
    const parsed: unknown = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed.filter(isRecent).slice(0, RECENT_MAX) : []
  } catch {
    return []
  }
}

function write(user: string, list: RecentResource[]): void {
  try {
    window.sessionStorage.setItem(key(user), JSON.stringify(list))
  } catch {
    // Storage off or full: the list is a convenience.
  }
}

/** Puts `entry` first (once), keeps at most RECENT_MAX, and returns the new list. */
export function rememberRecent(user: string | null, entry: RecentResource): RecentResource[] {
  if (!user) return []
  const list = [entry, ...readRecent(user).filter((r) => r.uid !== entry.uid)].slice(0, RECENT_MAX)
  write(user, list)
  return list
}

export function forgetRecent(user: string | null, uid: string): RecentResource[] {
  if (!user) return []
  const list = readRecent(user).filter((r) => r.uid !== uid)
  write(user, list)
  return list
}

export function clearRecent(user: string | null): void {
  if (!user) return
  try {
    window.sessionStorage.removeItem(key(user))
  } catch {
    // Nothing to clear without storage.
  }
}

/** When a session ends: every user's list in this tab. */
export function clearAllRecent(): void {
  try {
    const store = window.sessionStorage
    const keys = Array.from({ length: store.length }, (_, i) => store.key(i)).filter((k): k is string => k?.startsWith(PREFIX) ?? false)
    for (const k of keys) store.removeItem(k)
  } catch {
    // Nothing to clear without storage.
  }
}
