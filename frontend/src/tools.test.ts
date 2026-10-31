import { describe, expect, it } from 'vitest'
import { defaultTools } from './tools'

describe('the tools Run now and a new schedule tick', () => {
  const run = (connection_id: number, tool: string, status: string) => ({ connection_id, tool, status })
  const runs = [run(1, 'vulnerabilities', 'complete'), run(2, 'vulnerabilities', 'partial'), run(3, 'vulnerabilities', 'failed'), run(4, 'prowler', 'complete')]

  it('ticks Steampipe, Prowler and CloudFox always', () => {
    expect(defaultTools([], [])).toEqual(['steampipe', 'prowler', 'cloudfox'])
    expect(defaultTools(runs, [4])).toEqual(['steampipe', 'prowler', 'cloudfox'])
  })

  it('ticks Vulnerabilities only when it ran on every chosen connection', () => {
    expect(defaultTools(runs, [1])).toEqual(['steampipe', 'prowler', 'cloudfox', 'vulnerabilities'])
    expect(defaultTools(runs, [1, 2])).toContain('vulnerabilities')
    expect(defaultTools(runs, [1, 3])).not.toContain('vulnerabilities') // its last run failed
    expect(defaultTools(runs, [1, 4])).not.toContain('vulnerabilities') // never ran there
  })
})
