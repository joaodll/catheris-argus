import { describe, expect, it } from 'vitest'
import { byName, parseTags, tagParams, tagWords, withValues, type TagPair } from './tagFilter'

describe('the Tag filter', () => {
  it('reads valid pairs from the URL, each once, and ignores anything else', () => {
    const team = JSON.stringify(['Team', 'payments'])
    const odd = JSON.stringify(['a=b:c/d', 'x=y'])
    const parsed = parseTags([team, team, odd, 'Team=payments', '["one"]', JSON.stringify(['', 'v']), JSON.stringify(['k', 1])])
    expect(parsed).toEqual([
      ['Team', 'payments'],
      ['a=b:c/d', 'x=y'],
    ])
    expect(parseTags(undefined)).toEqual([])
    expect(tagParams(parsed)).toEqual([team, odd])
  })

  it('replaces one name’s values in place and removes a name left empty', () => {
    const tags: TagPair[] = [
      ['Team', 'a'],
      ['Stage', 'prod'],
    ]
    expect(withValues(tags, 'Team', ['b', 'c'])).toEqual([
      ['Team', 'b'],
      ['Team', 'c'],
      ['Stage', 'prod'],
    ])
    expect(withValues(tags, 'Team', [])).toEqual([['Stage', 'prod']])
    expect(withValues(tags, 'Owner', ['x'])).toEqual([...tags, ['Owner', 'x']])
    expect(byName(withValues(tags, 'Team', ['b', 'c']))).toEqual([
      { key: 'Team', values: ['b', 'c'] },
      { key: 'Stage', values: ['prod'] },
    ])
  })

  it('puts a name’s values in words, counting past three', () => {
    expect(tagWords('Team', ['a', 'b'])).toBe('Team = a or b')
    expect(tagWords('Team', ['a', 'b', 'c', 'd'])).toBe('Team = a or 3 more')
  })
})
