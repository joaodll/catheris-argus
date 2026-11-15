import { describe, expect, it } from 'vitest'
import { edgeTitle, edgeWord } from './edgeWords'

describe('edge words', () => {
  it('names every connection the map draws in plain words', () => {
    const drawn = ['ROUTES_TO', 'TRIGGERS', 'INTERNET_REACHABLE', 'RUNS_AS', 'CAN_ASSUME', 'IS_ADMIN', 'CAN_PRIVESC_TO', 'BELONGS_TO', 'OUTSIDER', 'HAS_CREDENTIAL', 'CAN_ESCALATE_TO', 'CAN_RUN_ON', 'MEMBER_OF', 'IN_NETWORK', 'ALLOWS_INGRESS', 'PROTECTED_BY', 'CAN_CONNECT_TO', 'HAS_POLICY', 'ACCESSES']
    for (const type of drawn) {
      const word = edgeWord(type)
      expect(word).toMatch(/^[a-z][a-z ]+$/) // words, never the raw type
      expect(word.length).toBeLessThanOrEqual(16) // fits the gap between columns
    }
    expect(edgeWord('ROUTES_TO')).toBe('routes to')
    expect(edgeWord('MEMBER_OF')).toBe('is in')
  })

  it('reads an unknown type as itself, and Systems Manager as reached through', () => {
    expect(edgeWord('NEW_KIND_OF_LINK')).toBe('new kind of link')
    expect(edgeWord('CAN_RUN_ON', 'any:ssm@123456789012')).toBe('can run commands through')
    expect(edgeWord('CAN_RUN_ON', 'arn:aws:ec2:us-east-1:123456789012:instance/i-1')).toBe('runs commands on')
    expect(edgeTitle('RUNS_AS')).toBe('Runs as')
  })
})
