import { describe, expect, it } from 'vitest'
import { readRecent, rememberRecent } from './recentResources'
import { endSession, session } from './useSession'

describe('endSession', () => {
  it("clears the session and what this tab remembers of the estate, every user's", () => {
    const entry = { uid: 'u', name: null, type: null, connectionId: 1, connectionName: null }
    rememberRecent('ana', entry)
    rememberRecent('bo', entry)
    session.value = { username: 'ana' } as typeof session.value
    endSession()
    expect(session.value).toBeNull()
    expect(readRecent('ana')).toEqual([])
    expect(readRecent('bo')).toEqual([])
  })
})
