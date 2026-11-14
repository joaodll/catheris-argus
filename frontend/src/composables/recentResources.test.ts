import { beforeEach, describe, expect, it, vi } from 'vitest'
import { RECENT_MAX, clearAllRecent, forgetRecent, readRecent, rememberRecent, type RecentResource } from './recentResources'

const entry = (uid: string): RecentResource => ({ uid, name: `name-${uid}`, type: 'aws_s3_bucket', connectionId: 1, connectionName: 'demo-prod' })

describe('recently opened resources', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    window.localStorage.clear()
  })

  it('keeps the newest first, once, and at most eight', () => {
    for (let i = 0; i < RECENT_MAX + 3; i++) rememberRecent('ana', entry(`r${i}`))
    rememberRecent('ana', entry('r5'))
    const list = readRecent('ana').map((r) => r.uid)
    expect(list).toHaveLength(RECENT_MAX)
    expect(list[0]).toBe('r5')
    expect(new Set(list).size).toBe(list.length)
    expect(list).not.toContain('r0')
  })

  it('is per user, and empty without one', () => {
    rememberRecent('ana', entry('a'))
    expect(readRecent('bo')).toEqual([])
    expect(readRecent(null)).toEqual([])
    expect(rememberRecent(null, entry('x'))).toEqual([])
  })

  it('forgets one entry, and sign-out clears every user', () => {
    rememberRecent('ana', entry('a'))
    rememberRecent('ana', entry('b'))
    rememberRecent('bo', entry('c'))
    window.sessionStorage.setItem('argus.theme', 'dark')
    expect(forgetRecent('ana', 'a').map((r) => r.uid)).toEqual(['b'])
    clearAllRecent()
    expect(readRecent('ana')).toEqual([])
    expect(readRecent('bo')).toEqual([])
    expect(window.sessionStorage.getItem('argus.theme')).toBe('dark') // only the map's lists
  })

  it('reads anything else stored there as an empty list', () => {
    window.sessionStorage.setItem('argus.map.recent:ana', '{not json')
    expect(readRecent('ana')).toEqual([])
    window.sessionStorage.setItem('argus.map.recent:ana', JSON.stringify([{ uid: 7 }, entry('ok'), 'x']))
    expect(readRecent('ana').map((r) => r.uid)).toEqual(['ok'])
  })

  it('stays out of local storage, so it ends with the tab', () => {
    rememberRecent('ana', entry('a'))
    expect(readRecent('ana').map((r) => r.uid)).toEqual(['a'])
    expect(window.localStorage.length).toBe(0)
  })

  it('survives storage being off', () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('denied')
    })
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('denied')
    })
    expect(readRecent('ana')).toEqual([])
    expect(() => rememberRecent('ana', entry('a'))).not.toThrow()
    get.mockRestore()
    set.mockRestore()
  })
})
