import { describe, expect, it } from 'vitest'
import { factLines, factLinks, factSub, marksOf, pillCount, sevToken, worstOf, type NodeFacts } from './mapFacts'

const covered = (over: Partial<NodeFacts> = {}): NodeFacts => ({
  misconfigurations: { open: 3, worst: 'high' },
  vulnerabilities: { open: 12, worst: 'critical', exploitable: 2, scanned: true },
  internet_reachable: true,
  ...over,
})

describe('the Security Map card facts', () => {
  it('counts open misconfigurations in the pill, never a zero', () => {
    expect(pillCount(covered())).toBe('3')
    expect(pillCount(covered({ misconfigurations: { open: 1200, worst: 'low' } }))).toBe('999+')
    expect(pillCount(covered({ misconfigurations: { open: 0, worst: null } }))).toBeNull()
    expect(pillCount(covered({ misconfigurations: null }))).toBeNull()
    expect(pillCount(null)).toBeNull()
  })

  it('names the worst severity and its tokens', () => {
    expect(worstOf(covered())).toBe('high')
    expect(worstOf(covered({ misconfigurations: { open: 2, worst: 'bogus' } }))).toBeNull()
    expect(sevToken('informational')).toBe('info')
    expect(sevToken('critical')).toBe('critical')
  })

  it('marks presence only', () => {
    expect(marksOf(covered())).toEqual({ internet: true, vulnerable: true, exploit: true })
    expect(marksOf(covered({ vulnerabilities: null, internet_reachable: false }))).toEqual({ internet: false, vulnerable: false, exploit: false })
  })

  it('says each fact in words, and why one is missing', () => {
    expect(factLines(covered(), 'prod')).toEqual([
      '3 open misconfigurations, worst High',
      '12 open vulnerabilities, 2 with a public exploit',
      "Reachable from the internet: Argus's rules confirm it",
    ])
    expect(factLines(covered({ misconfigurations: null, vulnerabilities: { open: 0, worst: null, exploitable: 0, scanned: false }, internet_reachable: false }), 'prod')).toEqual([
      'Misconfigurations: not covered (Prowler and CloudFox have not scanned prod)',
      'Not scanned for vulnerabilities',
    ])
    expect(factLines(covered({ misconfigurations: { open: 0, worst: null }, vulnerabilities: null, internet_reachable: false }), 'prod')).toEqual(['No open misconfigurations'])
    expect(factLines(null, 'prod')).toEqual([])
  })

  it('gives the List view words after the type', () => {
    expect(factSub(covered())).toEqual(['3 misconfigurations (High)', '12 vulnerabilities', 'Exploit', 'Internet reachable'])
    expect(factSub(covered({ misconfigurations: null, vulnerabilities: null, internet_reachable: false }))).toEqual(['Misconfigurations not covered'])
    expect(factSub(covered({ misconfigurations: { open: 0, worst: null }, vulnerabilities: null, internet_reachable: false }))).toEqual([])
  })

  it('links each fact to the list that counts it', () => {
    expect(factLinks(7)).toEqual({
      misconfigurations: { name: 'misconfigurations', query: { resource: '7', result: 'FAIL', muted: 'hide' } },
      vulnerabilities: { name: 'vulnerabilities', query: { resource: '7', muted: 'hide' } },
      internet: { name: 'misconfigurations', query: { resource: '7', result: 'FAIL', muted: 'hide', reach: 'confirmed' } },
    })
  })
})
